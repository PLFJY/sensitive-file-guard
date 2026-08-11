# Phase 11 — ssh-agent Load Flow

> Historical report, superseded by Phase 16. Client-declared executable
> identity fields were removed; the daemon now verifies a stopped direct child
> and constructs the target identity from `/proc` plus system `ssh-add`.

## Objective

Allow normal SSH/Git use while keeping raw key reads denied. A brokered
`guardctl ssh load PATH` command obtains a one-shot `SshLoadLease` bound to the
exact `ssh-add` invocation, lets `ssh-add` read the protected key exactly once,
then revokes the lease on process exit. No key bytes ever traverse IPC.

## Implemented behavior

### Lease data model (`guard-core::lease`)
[`SshLoadLease`](file:///home/plfjy/sensitive-file-guard/crates/guard-core/src/lease.rs#L46-L56)
carries everything the policy engine needs to make a deterministic decision
without re-reading any file:

- `id: LeaseId` — monotonic counter shared with migration leases.
- `resource: ProtectedResourceId` — the canonical path of the protected key.
- `uid: u32` — the authorizing user (from kernel-verified peer creds).
- `target: StableIdentity` — `exe + start_time + dev + ino` of the exact
  `ssh-add` invocation. `start_time` is read from `/proc/<pid>/stat` field 22
  *after* `fork` and *before* `execv`, so the value the parent reads equals the
  value `guardd` will read when fanotify fires.
- `expires_at: u64` — safety net (`DEFAULT_SSH_LOAD_DURATION_SECS = 30`,
  `MAX_SSH_LOAD_DURATION_SECS = 300`). The lease is one-shot and revoked on
  exit; the timeout only covers a `guardctl` crash.
- `revoked: bool`, `used: bool` — terminal-state flags. `used` flips to `true`
  in `decide_with_context` the instant a matching `AllowByLease` is issued, so
  the same lease can never authorize a second open even by the same process.

### Policy (`guard-core::policy::decide_ssh`)
[`decide_ssh`](file:///home/plfjy/sensitive-file-guard/crates/guard-core/src/policy.rs#L150-L181)
is unchanged from Phase 10 — it was already written to consume the `used` /
`revoked` / `expires_at` fields that Phase 11 now populates. The decision tree:

1. Scan `leases.ssh` for one matching `(resource, uid)`.
2. If scope matches but `target != proc_identity` → `Deny(IdentityMismatch)`
   (catches PID reuse: same pid, different start_time, or a different
   `ssh-add` binary).
3. If scope + identity match but `revoked` → `Deny(LeaseRevoked)`.
4. If scope + identity match but `used` → `Deny(OneShotLeaseUsed)`.
5. If scope + identity match but `now >= expires_at` → `Deny(LeaseExpired)`.
6. If scope + identity match and all flags clear → `AllowByLease(id)`.
7. If scope matched but no identity-matching lease was found →
   `Deny(IdentityMismatch)` (a different `ssh-add` invocation tried to reuse
   the grant).
8. If no scope match at all → `Deny(SshPrivateKeyRawRead)` (the default for
   `cat`, `cp`, editors, AI agents, git, an `ssh-add` without a lease, etc.).

### Authorization (`guardd::enforce::authorize_ssh_load`)
[`authorize_ssh_load`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/enforce.rs#L299-L341)
is the daemon-side entry point invoked by the IPC handler. It:

1. Canonicalizes the requested path.
2. Classifies it via the registry and requires
   `kind == ProtectedResourceKind::SshPrivateKey` — a `.pub` / reserved name /
   unenrolled path is rejected with a clear error mentioning
   `guardctl ssh protect`.
3. Checks `res.owner_uid == uid` so a user cannot load another user's key.
4. Computes `expires_at = now + min(DEFAULT, MAX)` (the constants are already
   ordered so this is always `DEFAULT_SSH_LOAD_DURATION_SECS = 30s`).
5. Allocates the next `LeaseId`, pushes the `SshLoadLease`, and returns
   `(lease_id, expires_at)`.

`uid` comes exclusively from `PeerCreds` (kernel-verified `SO_PEERCRED`); it is
never read from the request struct.

### One-shot `used` flag on the hot path
In
[`decide_with_context`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/enforce.rs#L445-L452),
immediately after `evaluate` returns a `Decision::AllowByLease(id)`, the engine
scans `leases.ssh` for the matching id and sets `used = true` before building
the audit record. This guarantees that even if `ssh-add` (or a compromised
process that stole the lease's PID + start_time) issues a second `open()` of
the same key, the next fanotify event sees `used == true` and denies with
`OneShotLeaseUsed`.

### IPC (`guard-ipc` + `guardd::ipc`)
Two new protocol elements in
[`guard-ipc/src/lib.rs`](file:///home/plfjy/sensitive-file-guard/crates/guard-ipc/src/lib.rs#L76-L97):

- `RequestOp::SshLoadAuthorize { path, ssh_add_exe, ssh_add_dev, ssh_add_ino, start_time }` —
  carries only the protected key *path* and the `ssh-add` file identity +
  start_time. **No key contents, no uid field** (uid is taken from peer creds).
- `ResponseBody::SshLoadAuthorized(SshLoadAuthorizedInfo { lease_id, path, uid, expires_at })` —
  returns the lease id and expiry for `guardctl` to print + revoke later. No
  key contents.

The daemon handler
[`handle_ssh_load_authorize`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/ipc.rs#L424-L461)
builds the `StableIdentity` from the request fields, calls
`authorize_ssh_load` under the engine mutex, logs the authorization (path +
lease_id + peer_uid + expires_at — never key bytes), and returns the response.
The mutex is held only for the registry lookup + lease push (microseconds).

### CLI (`guardctl ssh load`)
[`run_ssh_load`](file:///home/plfjy/sensitive-file-guard/apps/guardctl/src/main.rs#L712-L816)
implements the brokered fork+SIGSTOP+exec flow required by the spec:

1. Validate `SSH_AUTH_SOCK` is set (ssh-add needs a reachable agent).
2. Resolve `ssh-add` (`--ssh-add PATH` wins, else PATH search), canonicalize,
   and stat it to capture `(dev, ino)` for the lease's `StableIdentity`.
3. `fork()`; the child calls `raise(SIGSTOP)` so it cannot exec/open the key
   yet, then `execv("ssh-add", ["ssh-add", "<key>"])` on SIGCONT.
4. Parent `waitpid(WUNTRACED)` until the child is stopped.
5. Parent reads `start_time` from `/proc/<pid>/stat` (start_time is set at
   fork and is preserved across exec, so the value read now equals what guardd
   will read when fanotify fires for the exec'd ssh-add).
6. Parent sends `SshLoadAuthorize`. If the daemon refuses, the parent reaps
   the child (SIGCONT+SIGKILL) so `ssh-add` **never** execs without a lease.
7. Parent `SIGCONT`s the child → child execs ssh-add → ssh-add opens the key →
   fanotify fires → guardd matches the `StableIdentity` lease →
   `AllowByLease` → guardd sets `used = true`.
8. Parent `waitpid` for ssh-add to exit.
9. Parent best-effort revokes the lease via `LeasesRevoke` (the `used` flag +
   timeout already prevent reuse; revoke is belt-and-suspenders).
10. Report success/failure. `ssh-add`'s own stdout (key comment/fingerprint)
    passes through; `guardctl` itself never prints key bytes.

`fork` is called in a single-threaded CLI before any threads spawn, and the
child calls only async-signal-safe functions (`raise`, `execv`, `_exit`) before
`execv` replaces the image — the `unsafe` block has a SAFETY comment to that
effect.

## Hot-path impact

- `decide_ssh` is a linear scan over `leases.ssh`. In steady state this list is
  empty; during a load it holds exactly one entry for the duration of one
  `ssh-add` invocation. No allocation, no hashing.
- The `used = true` update is an in-place scan over the same short list — O(1)
  in practice.
- No new syscalls on the hot path for non-SSH resources; `decide_ssh` is only
  reached when `classify_fd` returns a `SshPrivateKey` resource.
- The IPC handler holds the engine mutex only for the registry lookup + lease
  push (microseconds); the `tracing::info!` log happens outside the mutex.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The privileged end-to-end script is
[`scripts/test-ssh-load-root.sh`](file:///home/plfjy/sensitive-file-guard/scripts/test-ssh-load-root.sh),
run as `sudo bash scripts/test-ssh-load-root.sh`. It requires `CAP_SYS_ADMIN`
for `FAN_CLASS_CONTENT` and is therefore provided for a human to run; the
non-interactive build agent cannot obtain it.

## Test results

`cargo fmt --check` — clean.
`cargo clippy --all-targets --all-features -- -D warnings` — clean.
`cargo test --all-features` — **176 passed, 0 failed.**

### Required tests (mapped to `11_SSH_AGENT_LOAD_FLOW.md`)

| Required test | Evidence |
| --- | --- |
| direct key read denied | `scripts/test-ssh-load-root.sh` Test 1 (cat the protected key => denied before any load) + `guardd::enforce::tests::ssh_load_lease_no_lease_denies_as_raw_read` (engine-level: ordinary process opening enrolled SSH key with no lease => `Deny(SshPrivateKeyRawRead)`) |
| `guardctl ssh load` succeeds | `scripts/test-ssh-load-root.sh` Test 3 (guardctl ssh load => succeeds under a one-shot lease) + `guardd::enforce::tests::ssh_load_lease_authorize_then_allowed_and_marked_used` (engine-level: authorize then decide => `AllowByLease` and `used` flips to true) |
| after load lease ends, direct key read is still denied | `scripts/test-ssh-load-root.sh` Test 5 (cat the protected key after the load => still denied; lease was one-shot + revoked) + `guardd::enforce::tests::ssh_load_lease_used_denies_second_open` (engine-level: a second open after `used=true` => `Deny(OneShotLeaseUsed)`) |
| `ssh-add -l` can see the loaded test identity | `scripts/test-ssh-load-root.sh` Test 4 (ssh-add -l lists the loaded "guard-ephemeral-load-test" identity) |
| a second unrelated `ssh-add`/process cannot reuse the expired one-shot lease | `scripts/test-ssh-load-root.sh` Test 2 (direct ssh-add without guardctl => fails to read the key) + Test 6 (a second guardctl ssh load works because it obtains a FRESH lease; a bare second ssh-add would still be denied) + `guardd::enforce::tests::ssh_load_lease_wrong_identity_denied` (engine-level: a process with a different StableIdentity cannot reuse the lease => `Deny(IdentityMismatch)`) |
| no key bytes appear in logs | `scripts/test-ssh-load-root.sh` Test 8 (audit events JSON + guardd decision log contain no "BEGIN OPENSSH PRIVATE KEY" header) + `guardd::enforce::tests::ssh_key_audit_record_has_no_secret_content` (serialized audit JSON has no `SSH_PRIVATE_KEY_MARKER`, no `content`/`key_bytes` keys) + `guard_ipc::tests::ssh_load_authorize_request_has_no_uid_field` (request carries no uid field; by construction it also carries no key contents) |

### Additional tests

| Test | Evidence |
| --- | --- |
| authorize_ssh_load: wrong uid errors | `guardd::enforce::tests::ssh_load_lease_wrong_uid_errors` |
| authorize_ssh_load: unprotected key errors | `guardd::enforce::tests::ssh_load_lease_unprotected_key_errors` |
| authorize_ssh_load: revoked lease denied on next open | `guardd::enforce::tests::ssh_load_lease_revoked_denied` |
| guardctl: SshLoadAuthorize request serializes with identity fields | `guardctl::tests::ssh_load_authorize_request_serializes_with_identity_fields` |
| guardctl: SshLoadAuthorized response parses | `guardctl::tests::ssh_load_authorized_response_parses` |
| guardctl: resolve_ssh_add explicit path wins | `guardctl::tests::resolve_ssh_add_explicit_path_wins` |
| guard-ipc: SshLoadAuthorize request has no uid field | `guard_ipc::tests::ssh_load_authorize_request_has_no_uid_field` |
| guard-ipc: SshLoadAuthorized response round-trips | `guard_ipc::tests::ssh_load_authorized_response_round_trips` |

### Full counts

- `guard_audit` — 5 passed (unchanged).
- `guard_browser` — 21 passed (unchanged).
- `guard_core` — 21 passed (unchanged; the SSH policy branch was added in
  Phase 03 / exercised in Phase 10 and covers `used` / `revoked` /
  `IdentityMismatch` / `OneShotLeaseUsed`).
- `guard-ipc` — 7 passed (5 from Phase 08/10 + 2 new Phase 11:
  `ssh_load_authorize_request_has_no_uid_field`,
  `ssh_load_authorized_response_round_trips`).
- `guard-ssh` — 10 passed (unchanged).
- `guard-test-fixtures` — 9 passed (unchanged).
- `platform-linux` — 29 passed (unchanged; `read_start_time` was added in
  Phase 06 and is reused by `guardctl ssh load`).
- `guardd` — 67 passed (60 from Phase 10 + 7 new Phase 11 enforce tests:
  `ssh_load_lease_authorize_then_allowed_and_marked_used`,
  `ssh_load_lease_used_denies_second_open`,
  `ssh_load_lease_revoked_denied`,
  `ssh_load_lease_wrong_identity_denied`,
  `ssh_load_lease_wrong_uid_errors`,
  `ssh_load_lease_unprotected_key_errors`,
  `ssh_load_lease_no_lease_denies_as_raw_read`).
- `guardctl` — 6 passed (3 from Phase 10 + 3 new Phase 11:
  `ssh_load_authorize_request_serializes_with_identity_fields`,
  `ssh_load_authorized_response_parses`,
  `resolve_ssh_add_explicit_path_wins`).
- `smoke` integration — 1 passed (unchanged).
- **Total: 176 passed, 0 failed.**

### Privileged end-to-end script (BLOCKED: requires root)

`scripts/test-ssh-load-root.sh` covers 9 scenarios that require
`CAP_SYS_ADMIN`:

1. `cat` the protected private key before any load => denied
2. direct `ssh-add` (no lease) => fails to read the key
3. `guardctl ssh load` => succeeds under a one-shot lease
4. `ssh-add -l` lists the loaded "guard-ephemeral-load-test" identity
5. after the load lease ends, `cat` the protected key => still denied
6. a second `guardctl ssh load` works (fresh lease) after `ssh-add -d`
7. every `ssh_load` lease in `leases list` is `revoked` or `used` (no live grant
   remains) — verified via python3 JSON check with a grep fallback
8. audit events JSON + guardd decision log contain no private-key header
9. clean daemon shutdown on SIGTERM

The script uses an isolated temp HOME, an ephemeral `ssh-keygen`-generated
ed25519 keypair, and an isolated `ssh-agent` on a controlled socket. It never
touches the developer's real `~/.ssh` or real `ssh-agent`. It contains no
network exfiltration code. The generated key + agent are destroyed with the
temp dir on exit.

**Status: BLOCKED for the non-interactive build agent** (cannot obtain
`CAP_SYS_ADMIN`). A human can run `sudo bash scripts/test-ssh-load-root.sh` to
execute the 9 privileged scenarios.

## Known limitations

1. **agent signing authority is not mediated (spec-documented).** Once a key is
   loaded into `ssh-agent`, same-user malware that can reach `SSH_AUTH_SOCK`
   may request signatures depending on agent/key constraints. V1 mediates raw
   private-key file access; it does not fully mediate agent signing authority.
   User options (confirmation prompts, lifetime constraints via
   `ssh-add -c` / `ssh-add -t`) are documented in the spec rather than silently
   changed.
2. **one-shot `used` is set on the first `AllowByLease`.** `ssh-add` opens the
   key exactly once in practice; if a future `ssh-add` implementation (or a
   wrapper) issued two opens, the second would be denied with
   `OneShotLeaseUsed` and `ssh-add` would fail. This is the intended
   fail-closed behavior.
3. **lease timeout is a safety net, not the primary revocation.** The lease is
   revoked by `guardctl` on `ssh-add` exit and marked `used` on the first
   allow. The 30s timeout only fires if `guardctl` crashes before sending the
   revoke. A crashed `guardctl` leaves the lease `used=true` (so it cannot be
   reused) but `revoked=false` until expiry — harmless, just untidy in
   `leases list`.
4. **fork+SIGSTOP+exec relies on Linux `start_time` semantics.** `start_time`
   is set at fork and preserved across exec, so reading it before SIGCONT is
   correct on Linux. This flow is Linux-specific (Phase 11 is Linux-only).
5. **`guardctl ssh load` does not verify the agent socket is the user's own.**
   A user who points `SSH_AUTH_SOCK` at another socket they can write to will
   load the key there. This is consistent with ssh-add's own model and the
   spec's documented limitation that agent authority is not mediated.
6. **privileged end-to-end tests are BLOCKED** for the non-interactive build
   agent (no `CAP_SYS_ADMIN`). The 9-scenario script is provided for a human to
   run; engine-level + IPC-level tests prove the logic without root.

## Security notes

- **uid is kernel-verified.** The daemon takes uid exclusively from
  `SO_PEERCRED` on the accepted socket; the request struct has no uid field
  (`guard_ipc::tests::ssh_load_authorize_request_has_no_uid_field` asserts
  this).
- **no key contents in IPC.** The request carries only the path + ssh-add file
  identity + start_time; the response carries only lease_id + path + uid +
  expires_at. Neither struct has a field that could hold key bytes.
- **no key contents in logs.** `tracing::info!` logs path + lease_id + peer_uid
  + expires_at. The audit record is the same `build_audit_record` used for all
  other decisions and contains no file contents
  (`ssh_key_audit_record_has_no_secret_content`).
- **fail-closed on authorization refusal.** If the daemon refuses the lease
  (wrong uid, unprotected key, etc.), `guardctl` reaps the stopped child with
  SIGCONT+SIGKILL so `ssh-add` never execs and never gets a chance to open the
  key.
- **lease binds to the exact invocation.** `StableIdentity` = canonical exe
  path + start_time + dev + ino. A different `ssh-add` binary, the same binary
  re-launched (different start_time), or PID reuse (same pid, different
  start_time) all fail to match → `Deny(IdentityMismatch)`.
