# Sensitive Data Firewall — Linux V1 Security Model

This document defines the guarantees, non-goals, and known limitations of the
Linux V1 implementation of the Sensitive Data Firewall (`guardd`). It is the
authoritative reference for what the firewall does and does not protect against.

## Mission

Prevent unauthorized local processes from reading protected local secrets —
browser session/auth data (cookies, session stores, saved credentials, key
material) and SSH private keys — **before** the protected file is successfully
opened. This is an access firewall, not an antivirus, EDR, or DLP.

## Guarantees

### 1. Pre-open denial on protected files
When `guardd` is running in enforcement mode (`FAN_CLASS_CONTENT` +
`FAN_OPEN_PERM` marks), an `open(2)` of a protected file by an unauthorized
process is denied **before** the file descriptor is handed to userspace. The
process receives `EPERM`; no bytes are read.

### 2. Inode-based classification (hardlink-proof)
Protected files are indexed by `(st_dev, st_ino)` in the enforcement engine.
A hardlink to a protected file (same inode, different path) is classified and
denied. A rename of a protected file (same inode, new name) is still denied.

### 3. Symlink resolution (symlink-proof)
`classify_fd` resolves the fd's real path via `/proc/self/fd/<fd>` and
canonicalizes it. A symlink to a protected file is resolved to the real path
and denied.

### 4. Canonical path resolution (relative-path-proof)
The registry's `classify` canonicalizes the path before lookup. A relative
path with `..` that resolves to a protected file is denied.

### 5. WAL/SHM sidecar coverage
SQLite WAL (`-wal`) and SHM (`-shm`) sidecar files for protected database
files (e.g. `Cookies` → `Cookies-wal`, `Cookies-shm`) are enrolled and denied
alongside the main database.

### 6. Process identity, not process name
Trust is never inferred from a process name or basename. An executable renamed
to look like a trusted browser stays untrusted. Identity is:
- canonical exe path (`/proc/<pid>/exe`)
- exe file identity (`st_dev` + `st_ino`)
- process start time (`/proc/<pid>/stat` field 22)
- trust tier (root-owned system package, hash-enrolled user-writable, or
  Unknown)

### 7. PID reuse detection
The identity cache is keyed by `(pid, start_time)`. A reused PID (same pid,
different start_time) invalidates the cache entry and forces a fresh resolve.
SSH load leases bind to `StableIdentity` (exe + start_time + dev + ino), so a
PID-reused process cannot reuse a one-shot lease.

### 8. UID verification
The requesting UID is taken from kernel-verified peer credentials
(`SO_PEERCRED`) on the IPC socket. It is never read from the request payload.
A process owned by a different UID than the resource owner is denied
(`WrongUid`) before identity is considered.

### 9. One-shot SSH load leases
A `SshLoadLease` authorizes exactly one `open()` of a protected SSH private
key by the exact `ssh-add` invocation (bound by `StableIdentity`). The `used`
flag is set on the first `AllowByLease`; a second open by the same process is
denied with `OneShotLeaseUsed`.

### 10. No secret contents in audit logs
Audit records contain metadata only (path, exe, uid, pid, decision, deny
reason, resource kind). They never contain file contents, cookie values,
passwords, key bytes, or private-key material.

### 11. Deterministic policy, no UI on the hot path
The authorization decision is a deterministic function of `(resource, process,
operation, leases)`. It never waits for a human UI. Deny is immediate; audit
and notification happen out-of-band.

### 12. Fail-closed on classification failure
If `classify_fd` cannot determine whether a fd is protected (race, unmarked
path, fd_path readlink failure), the decision is `Deny(UnclassifiedFd)` — the
engine fails closed, not open.

## Non-goals

### 1. Root compromise is out of scope
If an attacker has root, they can:
- kill `guardd`
- remove fanotify marks
- read files directly via `/dev/mem`, kernel modules, or `ptrace`
- modify the kernel

The firewall protects against **unprivileged** local processes (malware,
stolen session tokens, curious scripts, AI agents). It is not a rootkit
detector or a kernel hardening mechanism.

### 2. Already-open file descriptors are not retroactively denied
Fanotify `FAN_OPEN_PERM` intercepts **future** `open(2)` calls. A file
descriptor that was opened **before** the daemon applied the mark (or before
the daemon started) is not intercepted. The process holding that fd can read
the file. This is a fundamental fanotify limitation.

**Implication:** if `guardd` is started after the browser, the browser's
already-open cookie database fd is not protected. The recommended deployment
(Phase 14: systemd) starts `guardd` before any user session.

### 3. Inherited file descriptors are not intercepted
A child process that inherits an already-open fd from a parent (via `fork` /
`exec` without `O_CLOEXEC`) can read the file via the inherited fd. This is
the same fanotify limitation as above — the `open()` happened before the mark.

### 4. ssh-agent signing authority is not mediated
Once a key is loaded into `ssh-agent` (via the Phase 11 `SshLoadLease` flow),
same-UID malware that can reach `SSH_AUTH_SOCK` may request signatures
depending on agent and key constraints. V1 mediates raw private-key file
access; it does not mediate agent signing authority. Users can mitigate with
`ssh-add -c` (confirmation) or `ssh-add -t` (lifetime).

### 5. Not a DLP / network exfiltration blocker
The firewall prevents local file reads. It does not inspect or block network
traffic. A process that already has a secret in memory (legitimately or via a
pre-open fd) can exfiltrate it over the network.

### 6. Not an antivirus / EDR
The firewall does not scan file contents for malware, does not quarantine
files, and does not maintain reputation databases. It enforces an access
policy on a fixed set of protected paths.

## Linux-specific behavior

### Fail-open on daemon close
When `guardd` exits (crash, SIGTERM, SIGKILL), the fanotify group fd is closed
by the kernel. All `FAN_OPEN_PERM` marks are removed. **Files become
unprotected.** This is a fundamental property of fanotify: the marks live only
as long as the group fd is open.

**Mitigation (Phase 14):** the systemd unit is configured with `Restart=always`
and a short `RestartSec`. The daemon also has a `--watchdog` option (if
implemented) or relies on systemd's `WatchdogSec` for crash detection. During
the restart window, files are unprotected.

**This is fail-open, not fail-closed.** A fail-closed design would require
LSM (Linux Security Module) hooks or a kernel module that survives userspace
daemon death. That is out of scope for V1.

### Fanotify mount limitations
`fanotify_mark` with `FAN_MARK_MOUNT` marks an entire mount. The current
implementation uses `FAN_MARK_INODE` for individual files (critical browser
databases, SSH keys) and `FAN_MARK_FILESYSTEM` for tree protection where
available. On kernels < 5.13, `FAN_MARK_FILESYSTEM` is unavailable; tree marks
fall back to per-inode marks on discovered descendants.

### Recursive directory coverage
The `mark_tree` / `mark_trees` strategy marks the tree root directory with
`FAN_OPEN_PERM`. Fanotify on a directory mark intercepts opens of files
**directly under** that directory. New subdirectories created after the mark
may not be automatically covered unless `FAN_MARK_FILESYSTEM` is used.

**Known gap:** if a new nested directory is created and a file is opened in it
before `guardd` discovers and marks the new directory, that open is not
intercepted. This is a race window. The implementation does not claim
race-free tree coverage. The gap is documented and tested in Phase 13.

### FAN_Q_OVERFLOW
If the fanotify event queue overflows (too many events too fast), the kernel
delivers a `FAN_Q_OVERFLOW` event. `guardd` detects this in `parse_events`,
logs an `error!`, and continues processing. Overflow means some events may
have been dropped — denied opens during the overflow window may not have been
recorded in the audit log. The daemon does not crash on overflow.

**Mitigation:** the event buffer is 64KB (configurable). Under normal desktop
load, overflow is unlikely. A deliberate flood (thousands of opens/sec) could
trigger it — this is a denial-of-service consideration, not a bypass (the
overflowed events are opens that were already processed by the kernel's
fanotify permission check; overflow drops audit, not enforcement).

### Bind-mount / alternate-mount behavior
A file accessible via multiple mount points (bind mounts) has the same inode
on the underlying filesystem. Fanotify marks are inode-based for `FAN_OPEN_PERM`,
so a mark on one path protects the inode regardless of which mount point the
open comes through. However, `fanotify_mark` with `FAN_MARK_MOUNT` or
`FAN_MARK_FILESYSTEM` behaves differently across bind mounts — a mount mark
only covers the specific mount, not bind-mounted aliases.

**Recorded behavior:** for inode-based marks (the primary strategy for critical
files), bind mounts do not bypass protection. For tree/mount marks, a bind
mount to a different mount namespace may not be covered. This is an edge case
that is documented but not specifically tested in V1.

## Threat model summary

| Threat | Protected? | Notes |
| --- | --- | --- |
| Unprivileged process reads browser cookies | **Yes** | `FAN_OPEN_PERM` deny before open |
| Unprivileged process reads SSH private key | **Yes** | `FAN_OPEN_PERM` deny before open |
| Hardlink to protected file | **Yes** | Inode-based classification |
| Symlink to protected file | **Yes** | Canonical path resolution |
| Relative path `..` traversal | **Yes** | Canonicalize resolves `..` |
| Renamed protected file | **Yes** | Inode follows rename |
| PID reuse | **Yes** | start_time in identity + lease binding |
| Spoofed exe name | **Yes** | Canonical exe path + trust tier |
| AI coding agent reads secrets | **Yes** | No brand special-casing; agent = ordinary process |
| Root reads secrets | **No** | Root can kill daemon / bypass fanotify |
| Pre-open fd (opened before mark) | **No** | Fundamental fanotify limitation |
| Inherited fd from pre-open parent | **No** | Same fanotify limitation |
| ssh-agent signing misuse | **No** | Agent authority not mediated |
| Network exfiltration of in-memory secret | **No** | Not a network firewall |
| Daemon crash window | **No** | Fail-open on daemon death (systemd restart mitigates) |
| New nested dir race before mark | **No** | Documented tree-mark race window |

## Deployment recommendations

1. **Start `guardd` before user sessions** (Phase 14 systemd unit with
   `DefaultDependencies=yes`, `Before=graphical.target`).
2. **Use `Restart=always`** with a short `RestartSec` to minimize the
   crash-restart window.
3. **Enroll SSH keys at startup** via config (`ssh_keys` array) so they are
   protected from boot, not only after a manual `guardctl ssh protect`.
4. **Run `guardd` as root** (required for `FAN_CLASS_CONTENT` +
   `CAP_SYS_ADMIN`). The daemon does not need to run as the user; it resolves
   process identity via `/proc` regardless of the target process's UID.
5. **Audit log persistence** (Phase 07): the SQLite audit DB survives daemon
   restarts. Review `guardctl events` periodically.
