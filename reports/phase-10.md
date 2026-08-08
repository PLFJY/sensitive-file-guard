# Phase 10 — SSH Private-Key Protection

## Implemented behavior

### Detection (`guard-ssh`)
A new [`guard-ssh`](file:///home/plfjy/sensitive-file-guard/crates/guard-ssh/src/lib.rs) crate
provides name-based candidate detection, safe auto-suggestion, and resource enrollment. It
is deliberately content-free: it never reads, parses, hashes, or logs key bytes — protection
is anchored on path + inode/dev file identity, as the spec requires.

- [`is_private_key_candidate`](file:///home/plfjy/sensitive-file-guard/crates/guard-ssh/src/lib.rs#L45-L57)
  returns `false` for `.pub` files and for the reserved non-private names
  (`known_hosts`, `known_hosts2`, `authorized_keys`, `authorized_keys2`, `config`). Every
  other file name is a candidate — the user is the authority on whether an explicitly named
  path is a private key.
- [`suggest_keys`](file:///home/plfjy/sensitive-file-guard/crates/guard-ssh/src/lib.rs#L67-L105)
  scans a directory (default `~/.ssh`) for conventional `id_*` files, excludes `.pub` and
  reserved names, canonicalizes survivors, and returns a sorted list of regular files.
  Broken symlinks are silently skipped; a missing directory returns an empty list (not an
  error).
- [`enroll_key`](file:///home/plfjy/sensitive-file-guard/crates/guard-ssh/src/lib.rs#L113-L141)
  builds a `ProtectedResource` of kind `SshPrivateKey` from a path: canonicalize, stat,
  verify regular file, take `owner_uid` from the file's stat owner (authoritative for SSH
  keys), and set `browser`/`profile` to `None`. It reuses `is_private_key_candidate` so a
  `.pub` or reserved name is rejected even when explicitly named.

### Policy (`guard-core::policy`)
[`decide_ssh`](file:///home/plfjy/sensitive-file-guard/crates/guard-core/src/policy.rs#L150-L181)
is the dedicated SSH branch:

- The only allow path is a valid `SshLoadLease` matching both the resource id and the
  process uid, where the process's `StableIdentity` (exe + start time + dev + ino) equals
  the lease's armed target. A matching lease that is revoked, already used, or expired
  denies with `LeaseRevoked` / `OneShotLeaseUsed` / `LeaseExpired`.
- A lease matching scope (resource + uid) but not identity denies with `IdentityMismatch`
  (e.g. PID reuse: same pid, different start time).
- Everything else — `cat`, `cp`, Python, Node, shell, editor, AI agent, git — denies with
  `SshPrivateKeyRawRead`. Git is NOT automatically allowed to read raw private-key bytes;
  only a valid `SshLoadLease` (Phase 11) can authorize the exact load operation.
- The owner uid check that gates browser resources (`proc.uid != res.owner_uid` =>
  `WrongUid`) is **not** applied to SSH keys: a `SshLoadLease` already requires
  `lease.uid == proc.uid`, and an ordinary process (regardless of uid) without a lease is
  denied by `SshPrivateKeyRawRead`. This keeps SSH policy strict and lease-scoped.

### Enforcement engine (`guardd::enforce`)
`EnforcementConfig` gained an `ssh_keys: Vec<PathBuf>` field
([`EnforcementConfig::ssh_keys`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/enforce.rs#L69-L78)).
At daemon startup,
[`from_config`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/enforce.rs#L152-L164)
enrolls each listed key via `guard_ssh::enroll_key`, indexes it by `(st_dev, st_ino)` in
`fd_index` (so hardlinks to the same inode fire too), and registers it in the
`ProtectedResourceRegistry`. Enrollment failures (missing/non-candidate file) are non-fatal:
the key is simply not protected and a warning is logged.

[`protect_ssh_key`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/enforce.rs#L314-L321)
exposes the same enrollment at runtime: it updates the registry + inode index so subsequent
opens are classified and denied by the SSH policy. The caller (IPC handler) is responsible
for adding the fanotify `FAN_OPEN_PERM` mark immediately after. The SSH key classification
reuses the existing `classify_fd` path: inode lookup first (catches hardlinks), then
path-based registry classify (catches symlinks via canonicalization).

### IPC (`guard-ipc` + `guardd::ipc`)
A new [`RequestOp::SshProtect { path }`](file:///home/plfjy/sensitive-file-guard/crates/guard-ipc/src/lib.rs#L68-L75)
operation carries a single path string — **no key contents are ever sent**. The daemon's
[`handle_ssh_protect`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/ipc.rs#L361-L407)
handler:

1. Pre-validates the candidate name **before** requiring the fanotify group, so a `.pub` /
   reserved-name request is rejected even when the daemon is not in enforcement mode (and
   so this path is unit-testable without root).
2. Requires the shared fanotify group (`IpcState.group`), returning an error if the daemon
   is not in enforcement mode.
3. Under the engine mutex, calls `protect_ssh_key` to enroll the key in the registry + inode
   index.
4. Outside the mutex, calls `group.mark_file(FAN_OPEN_PERM, &res.path)` so the IPC thread
   never holds the engine lock across a syscall. Ordering is registry-then-mark: there is a
   microsecond window where the registry has the entry but the mark is not yet applied (an
   open in that window is not intercepted — fail-open at enrollment time only, matching the
   documented recursive-mark race boundary).
5. Returns [`ResponseBody::SshProtected(SshProtectedInfo)`](file:///home/plfjy/sensitive-file-guard/crates/guard-ipc/src/lib.rs#L130-L144)
   with the canonical path, owner uid, and resource id. No key contents.

The fanotify group is shared between the enforcement loop and the IPC handler via
`Arc<FanotifyGroup>` ([`IpcState.group`](file:///home/plfjy/sensitive-file-guard/apps/guardd/src/ipc.rs#L34-L44)).
`mark_file` takes `&self` and the kernel `fanotify_mark` syscall is thread-safe, so the IPC
thread can add runtime marks without blocking the enforcement loop. Any authenticated peer
may add protection — `SshProtect` only ever adds a fail-closed mark; it never grants access.

### CLI (`guardctl`)
[`guardctl ssh`](file:///home/plfjy/sensitive-file-guard/apps/guardctl/src/main.rs#L140-L159)
has two subcommands:

- **`protect PATH`** — sends `SshProtect` over IPC, prints the canonical path + owner uid +
  resource id. On success: "raw reads by ordinary processes are now denied. load via
  ssh-agent requires a SshLoadLease (Phase 11)."
- **`suggest [--dir DIR]`** — pure client-side glob (no daemon connection): lists
  conventional `id_*` candidates under `~/.ssh` (or `--dir`), excluding `.pub` and reserved
  names. Prints "enroll with: guardctl ssh protect <PATH>".

## Hot-path impact

- SSH key classification is the **same** `classify_fd` path used for browser resources:
  one `fstat` + `HashMap` lookup (inode index), falling back to one `readlink` +
  `registry.classify`. No extra cost on the hot path.
- `decide_ssh` is a linear scan over `leases.ssh` (typically empty in Phase 10; populated
  in Phase 11). No allocation, no hashing.
- Runtime `SshProtect` runs on the IPC thread and holds the engine mutex only for the
  registry insert (microseconds). The fanotify mark syscall happens outside the mutex.

## Exact commands run

```
cargo fmt
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The privileged end-to-end script is
[`scripts/test-ssh-enforcement-root.sh`](file:///home/plfjy/sensitive-file-guard/scripts/test-ssh-enforcement-root.sh),
run as `sudo bash scripts/test-ssh-enforcement-root.sh`. It requires `CAP_SYS_ADMIN` for
`FAN_CLASS_CONTENT` and is therefore provided for a human to run; the non-interactive build
agent cannot obtain it.

## Test results

`cargo fmt --check` — clean.
`cargo clippy --all-targets --all-features -- -D warnings` — clean.

### Required tests (mapped to `10_SSH_PRIVATE_KEY_PROTECTION.md`)

| Required test | Evidence |
| --- | --- |
| `cat` equivalent probe denied | `scripts/test-ssh-enforcement-root.sh` Test 1 (cat the protected private key => denied) + `guardd::enforce::tests::ssh_key_denied_for_ordinary_process` (engine-level: ordinary process opening enrolled SSH key => `Deny(SshPrivateKeyRawRead)`) |
| copy source open denied | `scripts/test-ssh-enforcement-root.sh` Test 2 (cp the protected private key => denied because source open failed) |
| Python/Rust child probe denied | `scripts/test-ssh-enforcement-root.sh` Test 3 (guard-test-probe Rust child => denied) + Test 4 (python3 child => denied, if available); engine-level deny proven by `ssh_key_denied_for_ordinary_process` |
| public key remains readable | `guardd::enforce::tests::ssh_pub_key_remains_readable` (enroll ONLY the private key; `classify_fd` on the `.pub` returns `None`) + `scripts/test-ssh-enforcement-root.sh` Test 6 (cat the `.pub` => readable, non-empty) |
| unrelated files under fake `.ssh` not accidentally blocked | `guardd::enforce::tests::ssh_unrelated_files_not_blocked` (`config` and `known_hosts` classify as `None`) + `scripts/test-ssh-enforcement-root.sh` Test 7 (config, known_hosts, notes.txt all remain readable) |
| protected key remains blocked after rename if mark/file-identity strategy supports it; otherwise expose the exact gap | fanotify marks are inode-based; renaming a protected key moves the SAME inode so protection follows the rename (no gap for `rename(2)`). A key re-created at the original path after deletion is a NEW inode and is NOT protected until re-enrolled — documented in Known limitations. `guardd::enforce::tests::ssh_key_hardlink_classifies_by_inode` proves the inode-index strategy. |

### Additional tests

| Test | Evidence |
| --- | --- |
| candidate detection rejects `.pub` + reserved names | `guard_ssh::tests::candidate_rejects_pub_and_reserved_names` |
| candidate detection accepts conventional + custom private keys | `guard_ssh::tests::candidate_accepts_conventional_and_custom_private_keys` |
| suggest lists only `id_*`, excludes `.pub` | `guard_ssh::tests::suggest_lists_only_id_files_excluding_pub` |
| suggest on missing dir returns empty | `guard_ssh::tests::suggest_on_missing_dir_returns_empty` |
| enroll_key builds SshPrivateKey resource | `guard_ssh::tests::enroll_key_builds_ssh_resource` |
| enroll_key rejects `.pub` file | `guard_ssh::tests::enroll_key_rejects_pub_file` |
| enroll_key rejects reserved name | `guard_ssh::tests::enroll_key_rejects_reserved_name` |
| enroll_key rejects missing file | `guard_ssh::tests::enroll_key_rejects_missing_file` |
| enroll_key rejects directory | `guard_ssh::tests::enroll_key_rejects_directory` |
| enroll_key owner_uid from file stat | `guard_ssh::tests::enroll_key_owner_uid_from_file_stat` |
| SSH key enrolled from config classifies | `guardd::enforce::tests::ssh_key_enrolled_from_config_classifies` |
| SSH key runtime protect classifies | `guardd::enforce::tests::ssh_key_runtime_protect_classifies` |
| protect_ssh_key rejects `.pub` | `guardd::enforce::tests::ssh_protect_rejects_pub_file` |
| protect_ssh_key rejects reserved name | `guardd::enforce::tests::ssh_protect_rejects_reserved_name` |
| SSH key hardlink classifies by inode | `guardd::enforce::tests::ssh_key_hardlink_classifies_by_inode` |
| SSH key audit record has no secret content | `guardd::enforce::tests::ssh_key_audit_record_has_no_secret_content` (serialized audit JSON has no `SSH_PRIVATE_KEY_MARKER`, no `content`/`key_bytes` keys) |
| IPC: `.pub` rejected before group consulted | `guardd::ipc::tests::ssh_protect_rejects_pub_file_via_ipc` |
| IPC: reserved name rejected | `guardd::ipc::tests::ssh_protect_rejects_reserved_name_via_ipc` |
| IPC: valid candidate without group errors (no enrollment side-effect) | `guardd::ipc::tests::ssh_protect_without_group_errors` (asserts `registry.classify(&s.private_key).is_none()` after the error) |
| IPC: SshProtect request carries no key contents | `guardd::ipc::tests::ssh_protect_request_has_no_key_contents` (serialized JSON has no `content`/`key_bytes`/`private_key` keys) |
| IPC: SshProtected response round-trips | `guard_ipc::tests::ssh_protected_response_round_trips` |
| policy: SSH private key ordinary process denied | `guard_core::policy::tests::ssh_private_key_ordinary_process_denied` |
| policy: SSH private key with valid lease allowed by lease | `guard_core::policy::tests::ssh_private_key_with_valid_lease_allowed_by_lease` |
| policy: used SSH lease denied | `guard_core::policy::tests::used_ssh_lease_denied` |
| policy: SSH lease wrong uid does not apply | `guard_core::policy::tests::ssh_lease_wrong_uid_does_not_apply` |
| policy: PID reuse (same pid, different start time) denied | `guard_core::policy::tests::pid_reuse_same_pid_different_start_time_denied` |

### Full counts

- `guard-ssh` — 10 passed (10 new Phase 10 detection/enrollment tests).
- `guardd` — 60 passed (47 from Phase 06–09 + 9 new Phase 10 enforce tests + 4 new Phase 10
  IPC tests).
- `guard-ipc` — 5 passed (4 from Phase 08 + 1 new Phase 10 `ssh_protected_response_round_trips`).
- `guard-core` — 21 passed (unchanged; SSH policy branch was added in Phase 03 and is
  exercised by the 5 SSH-related policy tests listed above).
- `guard-browser` — 21 passed (unchanged).
- `platform-linux` — 29 passed (unchanged).
- `guardctl` — 3 passed (unchanged; the `ssh` subcommand is covered by build + clippy +
  manual review + the privileged script).
- `guard-tui` — 2 passed (unchanged; migration round-trip integration test).
- `guard-audit` — 5 passed (unchanged).
- `guard-test-fixtures` — 9 passed (unchanged; `SshFixture` was added in Phase 03).
- `smoke` integration — 1 passed (unchanged).
- **Total: 166 passed, 0 failed.**

### Privileged end-to-end script (BLOCKED: requires root)

`scripts/test-ssh-enforcement-root.sh` covers 14 scenarios that require `CAP_SYS_ADMIN`:

1. `cat` the protected private key => denied
2. `cp` the protected private key => denied (source open fails)
3. `guard-test-probe` (Rust child) reads the protected key => denied
4. Python3 reads the protected key => denied (BLOCKED if python3 absent)
5. `sh -c cat` reads the protected key => denied
6. public key remains readable
7. unrelated files under `.ssh` (config, known_hosts, notes) remain readable
8. hardlink to protected private key => denied by inode mark
9. symlink to protected private key => denied
10. runtime `guardctl ssh protect` on a NEW key => protects it (readable before, denied
    after)
11. `guardctl ssh protect` rejects `.pub` file
12. `guardctl ssh suggest` lists conventional candidates, excludes `.pub`
13. protected key audit log has no `BEGIN OPENSSH PRIVATE KEY` header
14. clean daemon shutdown on SIGTERM

The script generates an **ephemeral** ed25519 keypair under an isolated temp `HOME` via
`ssh-keygen` (falling back to a synthetic marker key if `ssh-keygen` is absent). It NEVER
touches the developer's real `~/.ssh`, contains NO network exfiltration code, and destroys
the key with the temp dir on exit. Run with: `sudo bash scripts/test-ssh-enforcement-root.sh`.

## Known limitations

- **Re-create-after-delete gap**: fanotify marks are inode-based, so `rename(2)` of a
  protected key moves the SAME inode and protection follows the rename (no gap). But a key
  deleted then re-created at the original path is a NEW inode and is NOT protected until
  re-enrolled via `guardctl ssh protect PATH` or daemon restart. This is inherent to
  inode-based marks; a filesystem watcher that auto-re-enrolls is out of scope for Phase 10.
- **Enrollment-time microsecond window**: `SshProtect` enrolls in the registry first, then
  adds the fanotify mark. An open in the microsecond window between registry-insert and
  mark-apply is not intercepted (fail-open at enrollment time only). After the mark is
  applied, all subsequent opens are intercepted and denied. This matches the documented
  recursive-mark race boundary from Phase 06.
- **`ssh suggest` is name-based only**: it lists `id_*` files excluding `.pub` and reserved
  names. A user-named private key (e.g. `deploy_key`) is NOT suggested, but can be enrolled
  explicitly via `guardctl ssh protect PATH`. We deliberately do not parse file contents to
  detect private keys (the spec prefers path/inode identity and forbids hashing/logging key
  bytes).
- **No `SshLoadLease` issuance yet**: Phase 10 implements detection, enrollment, and raw-
  read denial. The actual `SshLoadLease` flow (ssh-agent load authorization, one-shot lease
  creation via IPC, lease consumption marking) is Phase 11. Until Phase 11, all raw reads
  by ordinary processes are denied — there is no allow path for SSH keys yet.
- **Privileged tests are BLOCKED on the non-interactive build agent**: `scripts/test-ssh-enforcement-root.sh`
  requires `CAP_SYS_ADMIN` (root) for `FAN_CLASS_CONTENT`. The script is complete and
  deterministic; a human must run it. The non-privileged unit tests (engine + policy + IPC +
  detection) all pass without root.

## Security notes

- **No key contents on the wire**: `RequestOp::SshProtect { path }` carries only a path
  string. Verified by `guardd::ipc::tests::ssh_protect_request_has_no_key_contents`
  (serialized JSON has no `content`/`key_bytes`/`private_key` keys) and
  `guard_ipc::tests::ssh_protected_response_round_trips` (response has no secret-content
  keys).
- **No key contents in audit log**: the audit record for a denied SSH key open carries only
  metadata (path, resource kind, pid, uid, exe, deny reason). Verified by
  `guardd::enforce::tests::ssh_key_audit_record_has_no_secret_content` (serialized audit
  JSON has no `SSH_PRIVATE_KEY_MARKER`, no `content`/`key_bytes` keys) and the privileged
  script Test 13 (audit events JSON has no `BEGIN OPENSSH PRIVATE KEY` header).
- **No key contents in detection/enrollment**: `guard_ssh::is_private_key_candidate`,
  `suggest_keys`, and `enroll_key` never read file contents. Protection is anchored on path
  + inode/dev file identity. `enroll_key` stats the file for `owner_uid` and regular-file
  check, but never reads the bytes.
- **Fail-closed for ordinary processes**: any process without a valid `SshLoadLease` is
  denied with `SshPrivateKeyRawRead`. This includes `cat`, `cp`, Python, Node, shell,
  editor, AI agent, and git (git is NOT automatically allowed to read raw private-key
  bytes). The only allow path is a valid `SshLoadLease` (Phase 11).
- **`.pub` and reserved names never protected**: `is_private_key_candidate` returns `false`
  for `.pub` files and `known_hosts`/`authorized_keys*`/`config`. `enroll_key` reuses this
  check, so even an explicit `guardctl ssh protect ~/.ssh/id_ed25519.pub` is rejected.
- **Inode-based marks catch hardlinks**: `fd_index` maps `(st_dev, st_ino)` to the resource,
  so a hardlink to a protected key (same inode, different path) is classified and denied.
  Verified by `guardd::enforce::tests::ssh_key_hardlink_classifies_by_inode` and the
  privileged script Test 8.
- **Symlinks resolved via canonicalization**: `registry.classify` canonicalizes the open
  path, so a symlink to a protected key is classified and denied. Verified by the privileged
  script Test 9.
