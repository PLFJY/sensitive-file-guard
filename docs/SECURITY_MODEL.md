# Sensitive Data Firewall — Linux V1 Security Model

This document defines the guarantees, non-goals, and known limitations of the
Linux V1 implementation of the Sensitive Data Firewall (`guardd`). It is the
authoritative reference for what the firewall does and does not protect against.

**Acceptance state:** implementation-complete Alpha; all required privileged
suites were executed on the tested Arch host, but security acceptance remains
pending because the conservative topology race was reproducibly readable in
10,000/10,000 atomic-replacement iterations. Do not use real secrets yet.

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

The client cannot declare that identity. It submits only a stopped child PID;
the daemon verifies that the child is the IPC peer's direct child, is stopped,
has the same UID/GID, and combines its kernel start time with the daemon-chosen,
root-owned system `ssh-add` inode. The child's `SSH_AUTH_SOCK` must name a Unix
socket owned by the requesting UID. The daemon connects to it, obtains the
listener's `SO_PEERCRED`, and verifies the listener PID/start time/executable
dev+inode against the root-owned, non-writable system OpenSSH `ssh-agent`.
These facts and the stopped child are checked again after polkit.

Before releasing the child, guardd hardlinks the verified socket inode below a
root-controlled, non-writable directory on the same filesystem. The child gets
only this pinned pathname, so replacing the user-controlled original pathname
after approval cannot redirect cooperative `guardctl`. The permission-event
hot path also reads the live `ssh-add` environment and requires
`SSH_AUTH_SOCK` to equal that lease's pin. A malicious client that resumes the
real system binary with the replaced original path is therefore denied. The
child uses the absolute system `ssh-add` path and an exact environment
containing only the pinned `SSH_AUTH_SOCK` and `LC_ALL=C`; loader and askpass
injection variables are not inherited. Polkit user authorization is required
for non-root requests.

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

### 13. Dynamic resource rediscovery
An inotify watcher is established before initial fanotify marking and watches
every directory below enrolled browser roots. Create, move, delete, and
attribute changes trigger full rediscovery, inode-index reconstruction, and
fanotify remarking. Replaced Cookie databases, new sidecars, new profiles, and
new nested storage directories therefore eventually become protected without
a daemon restart. This is a convergence property, not a race-free pre-open
guarantee: the tested replacement interval was readable before the new mark
was installed.

### 14. Migration capability lifecycle
A `MigrationAccessLease` starts `Armed` for one enrolled executable identity.
An armed lease does not authorize in the pure policy engine. On first matching
access, the enforcement engine binds it to the exact browser root process
(PID + start time + executable path/dev/inode). Only that process tree can use
the capability; it becomes dead when the root process exits or the PID is
reused.

## Security-sensitive IPC authorization

The socket is a transport boundary, not an authorization grant. Its installed
mode is `0660 root:guardd-users`; every connection gets kernel credentials from
`SO_PEERCRED`.

| Operation | Caller and independent verification | Capability and authorization |
| --- | --- | --- |
| `MigrationAuthorize` | peer UID/PID from `SO_PEERCRED`; source/profile/target must resolve to enrolled daemon configuration; peer start token must remain live | grants an armed, expiring process-tree capability; polkit for non-root |
| `SshProtect` | root or `stat`-verified file owner; canonical regular-file candidate, name, owner, and successful fanotify mark checked | adds protection but no read capability; polkit for non-root |
| `SshLoadAuthorize` | protected key owner; direct stopped child and trusted `ssh-add`; verified/pinned trusted `ssh-agent`; all kernel facts rechecked after authorization | grants one matching open for 30 seconds; polkit for non-root |
| `LeasesRevoke` | lease owner or root; ownership comes from daemon state | removes privilege; no polkit, and cross-user revocation is denied |

Polkit process subjects include PID, start time, and UID. While `pkcheck` is
pending, guardd monitors the IPC process's start token and the accepted socket;
it cancels if the peer exits, disconnects, or its PID is reused. A capability
whose response cannot be delivered is revoked. Client-supplied paths and
labels are never used as process identity.

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

### 7. Migration access is not read-only on fanotify
The fanotify event fd uses the flags selected by `fanotify_init`; `F_GETFL` on
that fd does not recover the triggering process's `open(2)` mode. Linux V1
therefore exposes a process-tree-scoped `MigrationAccessLease`, not a
read-only guarantee. Enforcing read-only migration requires another boundary
such as an LSM or a sandbox around a daemon-controlled migration process.

## Linux-specific behavior

### Fail-open on daemon close
When `guardd` exits (crash, SIGTERM, SIGKILL), the fanotify group fd is closed
by the kernel. All `FAN_OPEN_PERM` marks are removed. **Files become
unprotected.** This is a fundamental property of fanotify: the marks live only
as long as the group fd is open.

**Mitigation (Phase 14):** the systemd unit is configured with `Restart=always`
and `RestartSec=2`. The privileged systemd suite observed automatic restart and
mark reconstruction after `SIGKILL`. During that restart interval, files are
unprotected.

**This is fail-open, not fail-closed.** A fail-closed design would require
LSM (Linux Security Module) hooks or a kernel module that survives userspace
daemon death. That is out of scope for V1.

### Fanotify mount limitations
The current implementation uses inode marks for individual critical files and
recursive directory marks for storage trees. It does not currently use
`FAN_MARK_MOUNT` or `FAN_MARK_FILESYSTEM`.

### Recursive directory coverage
The `mark_tree` / `mark_trees` strategy marks the tree root directory with
`FAN_OPEN_PERM`. Fanotify on a directory mark intercepts opens of files
**directly under** that directory. New subdirectories created after the mark
may not be automatically covered unless `FAN_MARK_FILESYSTEM` is used.

The persistent topology watcher discovers and marks new directories. A
create/move notification → rediscovery → fanotify mark race remains; the
implementation does not claim race-free tree coverage. On the tested Arch host
and `/tmp` tmpfs, an atomic Cookie replacement followed by an immediate read
succeeded in 10,000/10,000 iterations. Protection converged with
p50/p95/p99/max delays of 1171/2225/2347/4039 microseconds. These numbers are an
empirical result, not a universal upper bound.

This makes filesystem-scope permission monitoring a requirement for the next
promotion candidate. A Strict Mode design should apply `FAN_MARK_FILESYSTEM`,
classify every permission event before allowing unrelated objects, and be
benchmarked for latency and queue overflow. It is not implemented in Linux V1.

Configured SSH-key parent directories are watched as well, so configured keys
are remarked after inode replacement. A key enrolled only at runtime is not yet
added to the watch-root set; if its parent is otherwise unwatched, replacing
that key requires `guardctl ssh protect` again.

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
| New nested dir before its mark | **No** | Documented and measured topology window |
| Replaced Cookie inode after watcher convergence | **Yes** | Rediscovered without restart |
| Immediate read of a replacement Cookie inode | **No** | 10,000/10,000 reads succeeded in the tested stress run |

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
6. Put interactive users in `guardd-users` for socket transport. This does not
   authorize mutations: migration and SSH policy changes separately require
   polkit. Log out and back in after installation so both the shell and the
   existing `systemd --user` manager receive the new supplementary group.
   Desktop notifications run as `guard-notify` in the user's session.
