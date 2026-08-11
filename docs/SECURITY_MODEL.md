# Sensitive Data Firewall — Linux V1 Security Model

This document defines the guarantees, non-goals, and known limitations of the
Linux V1 implementation of the Sensitive Data Firewall (`guardd`). It is the
authoritative reference for what the firewall does and does not protect against.

**Acceptance state:** **SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST only in
`strict-filesystem` mode for browser protection.** SSH behavioral containment
requires a separate privileged BPF acceptance matrix and is not accepted until
that matrix passes. Previously accepted browser suites were executed.
Conservative mode remains implementation-complete but is not promoted because
its replacement race remained readable in 10,000/10,000 iterations.

## Mission

Prevent unauthorized local processes from reading protected browser-session
data **before** access and protect SSH keys through a separate, capability-
gated model. This is not an antivirus, EDR, DLP, or payload-inspection product.

Browser resources remain denied before access. SSH private keys use an exact
`FAN_ACCESS_PERM` file mark so the daemon observes an actual read request,
rather than adding filesystem-wide read mediation. Protected SSH-key reads are
always allowed and reported, including when the behavioral backend is
unavailable. When active, the BPF LSM backend correlates the exact reader
process tree and blocks actual external IPv4/IPv6 sends at `socket_sendmsg`
while allowing AF_UNIX, AF_NETLINK, and IPv4/IPv6 loopback. Backend status is
reported separately and is never filesystem-read authority. The canonical
contract and state machine are in [SSH_BEHAVIOR_MODEL.md](SSH_BEHAVIOR_MODEL.md).

## Guarantees

### 1. Pre-open denial on protected files
When `guardd` is running in enforcement mode (`FAN_CLASS_CONTENT` +
`FAN_OPEN_PERM` marks), an `open(2)` of a protected file by an unauthorized
process is denied **before** the file descriptor is handed to userspace. The
process receives `EPERM`; no bytes are read.

### 2. Inode and hardlink-alias classification
Protected files are indexed by `(st_dev, st_ino)` in the enforcement engine.
A hardlink to a protected file (same inode, different path) is classified and
denied. A rename of a protected file (same inode, new name) is still denied.
In Strict Mode, an as-yet-unindexed event inode with `st_nlink > 1` triggers a
synchronous metadata-only search of enrolled namespaces before allow. This
closes the tested “hardlink outside the profile, then move the new inode over
Cookies, then open the alias” first-open case without imposing that scan on the
normal `st_nlink == 1` path. The 10,000-iteration alias stress had zero
recoveries. This search can make an unrelated hardlinked-file open slower; it
does not open protected contents.

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
flag is set on the first `AllowByLease`. A second open cannot reuse that lease,
but it follows the ordinary SSH behavioral path and is therefore allowed,
reported, and observed for immediate external sends.

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

### 12. Classification failure boundaries
Browser `FAN_OPEN_PERM` classification failures produce
`Deny(UnclassifiedFd)` so browser protection remains fail-closed. The narrow
SSH `FAN_ACCESS_PERM` path never denies a read: if key classification or
process identity cannot be resolved, guardd allows immediately and reports as
much metadata as it can. Missing identity cannot be treated as permission to
send-block an unrelated process tree.

### 13. Conservative dynamic resource rediscovery
An inotify watcher is established before initial fanotify marking and watches
every directory below enrolled browser roots. Create, move, delete, and
attribute changes trigger full rediscovery, inode-index reconstruction, and
fanotify remarking. Replaced Cookie databases, new sidecars, new profiles, and
new nested storage directories therefore eventually become protected without
a daemon restart. This is a convergence property, not a race-free pre-open
guarantee: both 10,000-iteration conservative runs read every immediate
replacement before the new mark was installed.

### 14. Migration capability lifecycle
A `MigrationAccessLease` starts `Armed` for one enrolled executable identity.
An armed lease does not authorize in the pure policy engine. On first matching
access, the enforcement engine binds it to the exact browser root process
(PID + start time + executable path/dev/inode). Only that process tree can use
the capability; it becomes dead when the root process exits or the PID is
reused.

### 15. Strict filesystem first-open enforcement
`strict-filesystem` deduplicates protected roots by filesystem device and
installs `FAN_MARK_FILESYSTEM | FAN_OPEN_PERM` on every required filesystem.
Every future regular-file open is therefore intercepted even if the inode did
not exist during discovery. Classification is ordered as:

1. live structural sensitive path below a configured browser root or exact
   configured SSH-key path;
2. known `(st_dev, st_ino)` resource for stable concrete files;
3. exceptional multi-hardlink alias search;
4. immediate unrelated allow.

Short-lived descendants of browser storage/session trees (SQLite journals,
WALs, and similar files) are not permanently pinned in the inode index. Their
inodes can be reused immediately after deletion; retaining those entries would
misclassify unrelated files such as clipboard databases. Concrete critical
files and verified hardlinks retain inode identity across rename.

A structural path hit is promoted to the shared `(st_dev, st_ino)` index
before guardd answers the permission event. This applies whether policy allows
or denies that first open. Once an object has been observed as sensitive, a
subsequent rename outside the configured namespace therefore remains protected
without waiting for topology rediscovery. Phase 19.1 exercised both the owning
browser ALLOW path and the unauthorized DENY path before an immediate
rename-away; neither external retry recovered the synthetic object.

The unrelated path performs fstat, a small inode-index read, fd-path readlink,
and structural prefix/name checks. It does not resolve process ancestry, hash
executables, query packages or SQLite, or emit audit records. Process identity
and policy are evaluated only for a protected candidate. The classifier covers
Chromium Local State, Cookies sidecars/replacements, Login/Web Data, Sessions,
Session Storage, Local Storage and IndexedDB, plus Firefox cookies sidecars,
logins/key material, sessionstore-backups and storage descendants.

Kernel-reported guardd PID events are allowed before the engine mutex. Audit,
topology, config/state, startup and shutdown activity therefore cannot create
the lock/open/permission-event deadlock. The strict startup sequence opens its
audit dependency before installing filesystem marks. The executed startup,
refresh, audit, topology, concurrency and shutdown tests observed no deadlock.

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
| `IncidentResolve` | incident owner or root may locate the exact ID; daemon then rechecks the peer's live PID/start token | typed `block_and_quarantine`, `block`, or `allow`; each crosses non-cached `org.guardd.incident-resolve` polkit authorization |

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
access behavior; it does not deny reads or mediate agent signing authority. Users can mitigate with
`ssh-add -c` (confirmation) or `ssh-add -t` (lifetime).

### 5. SSH behavioral model limits
Even on a compatible BPF-LSM deployment, the model is only: protected SSH-key
read + short (default 10-second) window + same process/future-child actual
external IPv4/IPv6 TCP/UDP send. It does not prove that an attempted payload is
a key, inspect TLS/plaintext, or provide full taint tracking. AF_UNIX,
AF_NETLINK, and loopback are deliberately local-only exclusions. Deliberate
bypasses outside this V1 scope include sleeping past the window, arbitrary IPC
or shared-memory transfer to an already-running process, local temporary-file
handoff, root/kernel compromise, daemon/backend failure, and untested exotic
send paths. Loopback/local IPC is not the target. Backend unavailability is an
explicit degraded state: reads remain allowed and reported, but outbound
blocking is unavailable.

### 6. Not an antivirus / EDR
The firewall does not scan file contents for malware or maintain reputation
databases. Its SSH incident response may quarantine only a narrowly verified,
attributable direct executable or explicit script argument; it is not a
general-purpose malware quarantine engine.

### 7. Migration access is not read-only on fanotify
The fanotify event fd uses the flags selected by `fanotify_init`; `F_GETFL` on
that fd does not recover the triggering process's `open(2)` mode. Linux V1
therefore exposes a process-tree-scoped `MigrationAccessLease`, not a
read-only guarantee. Enforcing read-only migration requires another boundary
such as an LSM or a sandbox around a daemon-controlled migration process.

## Linux-specific behavior

### Browser executable portability and sandboxes
Browser authorization is an explicit enrollment of a configured profile root
and the canonical executable identity observed through `/proc/<pid>/exe` plus
`st_dev`/`st_ino`. Native package layouts differ across distributions, so the
deployment helper suggests only existing canonical final executable paths; it
does not treat `/usr/bin` launchers, `argv[0]`, a basename, or package metadata
as an identity. Omitting `owner_uid` is safe only for an existing profile root:
guardd stats that root and fails if it cannot.

`guardctl setup --home PATH` is the explicit deployment path for native
profiles. It requires an explicit home when invoked as root, writes only a new
non-empty `strict-filesystem` configuration after confirmation, and does not
start the daemon. It never guesses SSH keys or treats unsupported sandboxed
paths as browser enrollment. A missing configuration makes the provided unit
ineligible to start rather than allowing an empty policy to appear active.

Native Firefox and Debian Firefox ESR are ordinary Firefox-family enrollments
with separately configured executable/profile pairs. Typical ESR values are
`/usr/lib/firefox-esr/firefox-esr` and `~/.mozilla/firefox-esr`; no Debian
package-name exception exists. Brave, Edge, Vivaldi, and custom browser builds
remain available through the same explicit configuration mechanism.

Firefox WebStorage coverage includes both the modern `storage/` tree and the
legacy per-profile `webappsstore.sqlite` database with its WAL/SHM sidecars.
Its rollback-journal sidecar is covered too. The legacy database remains a
browser local-storage source used by extraction tools and can contain
authenticated web state.

Snap and Flatpak browser installations are not security-accepted in Linux V1.
Their application mount namespaces can make host `/proc/<pid>/exe` identity
and filesystem-mark/profile visibility differ from the application view. This
has not been equivalently privileged-tested, so discovery reports these forms
instead of enrolling them. Trusting a Snap name, Flatpak ID, or process name
would violate the process-identity invariant and is forbidden.

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

### Conservative versus Strict Filesystem Mode
Conservative mode preserves the original concrete-file and recursive-directory
marks. Inotify rediscovery eventually marks replacements and new directories,
but it is not a security boundary. The historical Phase 18 conservative run
allowed 10,000/10,000 immediate reads and converged at
1171/2225/2347/4039 microseconds p50/p95/p99/max. The Phase 19 rerun again
allowed 10,000/10,000, with 1178/2205/2331/3412 microseconds convergence.

Strict Mode marks each distinct filesystem containing configured browser roots
or configured SSH keys. It does not wait for inotify before classifying a new
path. The executed tests denied the first open of Chromium Cookies and
sidecars, Local State, session descendants, a new profile's Cookies, Firefox
cookies, storage and sessionstore descendants. The 10,000 replacement loop had
zero successful reads. Inotify remains for metadata/index maintenance and
Conservative compatibility.

Strict Mode startup requires every configured root/key to exist and every
deduplicated filesystem mark to succeed. Otherwise guardd exits without
printing ACTIVE. Status re-reads the fanotify fd's kernel `fdinfo`, compares
live `fanotify sdev:` entries with the required count, and reports DEGRADED if
a filesystem mark is lost. Runtime-only `SshProtect` still adds an inode mark;
it does not dynamically add a persistent strict filesystem namespace, so
replacement of a runtime-only key on a previously unmarked filesystem requires
reprotection.

### FAN_Q_OVERFLOW
If the fanotify event queue overflows (too many events too fast), the kernel
delivers a `FAN_Q_OVERFLOW` event. `guardd` detects this in `parse_events`,
logs an error, increments `fanotify_overflows`, and reports `DEGRADED`. Queue
overflow means guardd cannot prove every affected access was mediated; it is a
security degradation, not merely missing audit. The daemon does not request an
unlimited queue and does not hide overflow by claiming ACTIVE.

The bounded acceptance run combined 160,000 unrelated opens, 20,000 owning
browser opens, 300 denied/replacement opens, 400 IPC queries and topology/audit
activity. It processed 180,624 strict events with zero fanotify overflows,
audit drops, classifier failures, or deadlocks. This is evidence for the tested
load, not a proof that an intentional resource-exhaustion attack cannot
overflow the finite kernel queue.

The exceptional hardlink scan was also stressed directly with eight concurrent
readers opening an unrelated `st_nlink=2` inode 16,000 times. That deliberately
forced at least 16,000 protected-namespace scans, completed in 889 ms on the
small synthetic fixture, and produced zero overflow, audit drop, or classifier
failure. It does not prove resistance to arbitrary denial-of-service pressure
or predict cost for very large real profile trees.

### Bind-mount / alternate-mount behavior
`FAN_MARK_FILESYSTEM` covers the filesystem from all of its mount points. The
root acceptance test created a bind alias and observed denial through it for an
indexed protected inode. Creating mounts requires privilege outside the V1
unprivileged-attacker model; root can remove marks or kill guardd directly.
Cross-namespace/remount lifecycle combinations were not exhaustively tested.
The disposable tmpfs lifecycle test did unmount and re-create one protected
mount: the kernel filesystem-mark count fell to zero and status changed from
ACTIVE to DEGRADED. Guardd does not automatically attach the old policy to a
new superblock at the same path; restart is required to validate and mark it.

### Performance
On the tested ext4 filesystem, 100,000 ordinary opens fell from about 900,425
opens/s without guardd to 72,578 opens/s in Strict Mode (12.41x wall-time).
An owning synthetic browser achieved 34,046 protected opens/s; an unauthorized
probe was denied at 31,922 opens/s with 29.6/36.6/58.3/283.7 microseconds
p50/p95/p99/max. A cached workspace `cargo check` measured 0.1269s absent,
0.0607s conservative, and 0.0786s strict; those short runs are ordering/cache
noise and are recorded only as a usability smoke test. Strict remains opt-in.

## Threat model summary

| Threat | Protected? | Notes |
| --- | --- | --- |
| Unprivileged process reads browser cookies | **Yes** | `FAN_OPEN_PERM` deny before open |
| Unprivileged process reads SSH private key | **Observed, not denied** | Always allowed and reported; active BPF observes its exact process tree for immediate sends |
| Hardlink to protected file | **Yes** | Inode index; Strict also scans new multi-link aliases before allow |
| Symlink to protected file | **Yes** | Canonical path resolution |
| Relative path `..` traversal | **Yes** | Canonicalize resolves `..` |
| Previously indexed/classified concrete protected file after rename | **Yes** | Inode identity follows rename |
| New sensitive inode renamed away after its first classified open | **Yes** | Structural hit is indexed before FAN response |
| Inode only renamed through sensitive name, never opened there | **No** | `FAN_OPEN_PERM` does not mediate rename; explicit open-only boundary |
| PID reuse | **Yes** | start_time in identity + lease binding |
| Spoofed exe name | **Yes** | Canonical exe path + trust tier |
| AI coding agent reads secrets | **Yes** | No brand special-casing; agent = ordinary process |
| Root reads secrets | **No** | Root can kill daemon / bypass fanotify |
| Pre-open fd (opened before mark) | **No** | Fundamental fanotify limitation |
| Inherited fd from pre-open parent | **No** | Same fanotify limitation |
| ssh-agent signing misuse | **No** | Agent authority not mediated |
| Immediate external TCP/UDP send by recent key-reader tree | **Conditional** | Blocked before payload egress only while the BPF backend and exposure window are active |
| Delayed or uncorrelated network exfiltration | **No** | Not full DLP or information-flow tracking |
| Daemon crash window | **No** | Fail-open on daemon death (systemd restart mitigates) |
| New nested sensitive path, Strict | **Yes** | Filesystem mark + structural classifier; first attempt denied |
| New nested dir, Conservative | **No** | Documented and measured topology window |
| Replaced Cookie inode after watcher convergence | **Yes** | Rediscovered without restart |
| Immediate replacement Cookie, Conservative | **No** | 10,000/10,000 reads succeeded |
| Immediate replacement Cookie, Strict | **Yes** | 0/10,000 successful reads |
| New-inode external hardlink, Strict | **Yes** | 0/10,000 successful reads in targeted stress |

## Deployment recommendations

1. **Set `enforcement_mode` to `strict-filesystem`** for the accepted security
   boundary. Conservative is the lower-overhead compatibility mode and retains
   a known replacement race.
2. **Create a non-empty reviewed configuration first** with `sudo guardctl
   setup --home "$HOME"` for a native browser profile, then start `guardd`.
   The helper does not infer SSH keys; enroll those deliberately if needed.
3. **Start `guardd` before user sessions** (Phase 14 systemd unit with
   `DefaultDependencies=yes`, `Before=graphical.target`).
4. **Use `Restart=always`** with a short `RestartSec` to minimize the
   crash-restart window.
5. **Enroll SSH keys at startup** via config (`ssh_keys` array) so they are
   protected from boot, not only after a manual `guardctl ssh protect`.
6. **Run `guardd` as root** (required for `FAN_CLASS_CONTENT` +
   `CAP_SYS_ADMIN`). The daemon does not need to run as the user; it resolves
   process identity via `/proc` regardless of the target process's UID.
7. **Audit log persistence** (Phase 07): the SQLite audit DB survives daemon
   restarts. Review `guardctl events` periodically.
8. Put interactive users in `guardd-users` for socket transport. This does not
   authorize mutations: migration and SSH policy changes separately require
   polkit. Log out and back in after installation so both the shell and the
   existing `systemd --user` manager receive the new supplementary group.
   Desktop notifications run as `guard-notify` in the user's session.

## GTK control center boundary

`guard-ui` is an ordinary desktop-user process. It reads only daemon metadata,
the owner-readable configuration contract, and audit rows; it never opens
browser databases or SSH key contents. Browser discovery produces suggestions,
not trust. Every switch and policy edit is an in-memory candidate until the
user presses Apply.

Apply and service start/stop/restart use `pkexec guardctl privileged ...`.
That hidden helper accepts only the fixed `guardd.service` and fixed
`/etc/guardd/config.json`, requires root, caps stdin at 256 KiB, validates the
shared configuration contract, writes a mode-0640 root:guardd-users temporary
file, fsyncs and renames atomically, then restarts and health-checks guardd.
When the new daemon does not become active, the prior configuration is restored
and restarted. No arbitrary command, unit, destination, or shell string is
accepted. The Overview bundle switch also starts/stops the logged-in user's
fixed `guard-notify.service` through `systemctl --user`; this user service is
not elevated and is considered part of the complete desktop protection view.
The GTK process itself is never elevated.
