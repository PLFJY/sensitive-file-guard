# Phase 16 — Linux V1 Security Review / Hardening Pass 1

## Status

**IMPLEMENTED; NON-PRIVILEGED GATES PASS; PRIVILEGED ACCEPTANCE PENDING.**

No real browser profile, Cookie database, session token, password, or SSH
private key was read. Tests use synthetic fixtures and local-only probes.

## Changes

### Authoritative SSH load identity

- `SshLoadAuthorize` carries only `path` and a stopped child PID.
- `guardd` verifies direct parent PID, stopped state, UID, GID, and start time
  from `/proc`.
- The target executable identity comes from daemon-selected, root-owned,
  non-group/other-writable system `ssh-add`.
- The child's `SSH_AUTH_SOCK` must be an existing Unix socket owned by the peer
  UID.
- Non-root requests require the `org.guardd.ssh-load` polkit action.
- The CLI rejects a custom `--ssh-add` unless it canonicalizes to the same
  system executable.

This closes the original client-declared identity bypass. The daemon does not
yet create the `ssh-add` child itself; it authoritatively constructs the only
post-exec identity the lease will match and requires explicit polkit presence.
The prompt includes the exact key and agent socket. Privileged end-to-end
validation remains mandatory.

### Dynamic browser topology

- Added an inotify watcher over all directories below enrolled profile roots.
- Watch registration happens before initial fanotify marking.
- Create/move/delete/attribute events trigger rediscovery, inode-index rebuild,
  and fanotify remarking.
- Runtime SSH resources survive browser-registry refresh.
- A new privileged synthetic suite covers replacement Cookie and configured
  SSH-key inodes, a new nested tree, and new profile convergence.

This eliminates indefinite unprotection until restart. Conservative mode still
has a bounded watcher→mark race. Filesystem-scope strict mode is future work.

### Honest migration semantics

- Renamed the domain capability to `MigrationAccessLease`.
- Removed the unenforceable `read_only` field and the `F_GETFL` event-fd logic.
- IPC now reports `read_only_guaranteed: false`.
- Added `Armed`, `Bound`, and `Dead` lease states.
- First use binds to exact PID/start-time/executable identity; descendants must
  carry that exact root in their captured ancestor chain.
- Root process exit or PID reuse kills the bound state.

### IPC and policy mutation

- Service runs as `root:guardd-users`, yielding a `0660` group-accessible
  socket while retaining root fanotify authority.
- Installer creates `guardd-users` and adds the invoking sudo user.
- Transport membership does not authorize mutations: migration authorize,
  SSH protect, and SSH load use polkit.
- `ssh protect` checks owner UID before registry mutation and marks before
  publishing, so its enrollment interval is fail-closed.

### Desktop presentation

- Removed root-daemon `notify-send` execution.
- Added `guard-notify`, a user-session IPC consumer with no policy logic.
- Added a systemd user unit and installer support.

### Acceptance truthfulness

- Replaced the final report's `COMPLETE` claim with implementation-complete
  Alpha / privileged acceptance pending.
- Root-script rows are not marked PASS without an observed run.
- Added `scripts/test-hardening-root.sh`; there are now eight privileged suites.

## Quality gates

Executed in this environment:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
bash -n scripts/test-hardening-root.sh deploy/install.sh
```

Result: all three gates passed; `cargo test` ran **180 tests, 0 failed**.

## BLOCKED privileged acceptance

The following commands require root plus `CAP_SYS_ADMIN` and were not run in
this environment:

```sh
sudo bash scripts/test-fanotify-root.sh
sudo bash scripts/test-browser-enforcement-root.sh
sudo bash scripts/test-ssh-enforcement-root.sh
sudo bash scripts/test-bypass-root.sh
sudo bash scripts/test-ssh-load-root.sh
sudo bash scripts/test-systemd-root.sh
sudo bash scripts/test-agent-compat-root.sh
sudo bash scripts/test-hardening-root.sh
```

The deterministic scripts are the handoff for an Arch host. Their existence is
not counted as a pass.

Observed blocker:

```text
id -u                         => 1000
/proc/self/status CapEff      => 0000000000000000
bash scripts/test-hardening-root.sh
=> ERROR: run as root (fanotify FAN_OPEN_PERM requires CAP_SYS_ADMIN)
```

## Repository input gap

`AGENTS.md` names `sensitive-data-firewall-harness/00_GLOBAL_CONTRACT.md` and
`01_ARCHITECTURE_CONTEXT.md` as source-of-truth files, but neither exists in
this checkout or the visible workspace. This pass followed the constraints
restated in `AGENTS.md`; restoration of the source documents should be checked
before security acceptance.
