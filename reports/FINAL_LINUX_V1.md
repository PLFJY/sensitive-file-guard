# Linux V1 Final Acceptance Report

## Final decision

```text
SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST
```

This decision applies to explicit `strict-filesystem` mode on the tested Arch
host. Conservative mode is not promoted: it still allowed every immediate
replacement read in the 10,000-iteration race. The Alpha qualification and all
remaining non-goals below remain material.

No test accessed a real profile, Cookie, token, password, private key, or
existing agent. Fixtures were unique disposable Chromium/Firefox profiles,
ephemeral OpenSSH keys/agents and synthetic canaries. Exfiltration controls
used only AF_UNIX sockets under the disposable directory; no public network was
contacted.

## Tested environment

| Component | Observed value |
| --- | --- |
| Distribution | Arch Linux x86_64 |
| Kernel | `7.1.6-arch1-1` |
| systemd | `261.2-1` |
| OpenSSH | `10.4p1-3` |
| polkit | `127-3` |
| Rust/Cargo | `1.97.0` |
| Strict/race fixtures | `/tmp` tmpfs |
| Performance workload | ext4, `/dev/nvme0n1p3` |
| Host policy | `fs.protected_hardlinks=1`, `kernel.yama.ptrace_scope=1` |
| Base commit | `5159c1c` plus Phase 19 worktree |

## Accepted architecture

```text
guardctl / guard-tui                 guard-notify (user session)
          |                                      |
          +---------- Unix IPC / SO_PEERCRED ----+
                             |
                         guardd (root)
              policy / identity / leases / polkit
                  resource registry / audit
                             |
        FAN_MARK_FILESYSTEM + FAN_OPEN_PERM (Strict)
                             |
                    protected filesystems
```

The socket is `0660 root:guardd-users`. Membership grants IPC transport, not
mutation authority. `MigrationAuthorize`, `SshProtect` and `SshLoadAuthorize`
require real polkit for non-root callers. Event visibility is filtered by UID.
`guard-notify` is presentation-only and runs in the user session.

Two backend modes remain explicit:

- `conservative`: object/tree marks and inotify rediscovery, lower overhead,
  known replacement race.
- `strict-filesystem`: one permission mark per protected filesystem, structural
  first-open path classification and exceptional hardlink-alias validation.

Strict unrelated events avoid process ancestry, executable hashing, package
lookups, SQLite and audit. Only protected candidates enter the policy engine.
Every structural path hit is inserted into the inode index before the fanotify
response, whether its policy result is ALLOW or DENY. A later rename outside
the namespace therefore remains protected without waiting for inotify.
Guardd's kernel PID has a pre-lock self-event fast path, preventing audit and
topology activity from deadlocking the permission loop. Missing required roots
or failed filesystem marks abort startup rather than claiming ACTIVE.
Status reads the fanotify group's kernel fdinfo and reports DEGRADED if the
observed filesystem-mark count falls below the required count.

## Security result

| Measurement | Iterations | Unauthorized recoveries | Denied | Errors |
| --- | ---: | ---: | ---: | ---: |
| Conservative immediate replacement, Phase 19 | 10,000 | 10,000 | 0 | 0 |
| Strict immediate replacement | 10,000 | 0 | 10,000 | 0 |
| Strict new-inode external-hardlink alias | 10,000 | 0 | 10,000 | 0 |

The historical conservative result remains 10,000/10,000 recovered with
1171/2225/2347/4039 microseconds p50/p95/p99/max convergence. The fresh rerun
was 1178/2205/2331/3412 microseconds. Strict required no rediscovery wait.

Strict first-attempt tests covered Chromium Network/Cookies, Cookies-wal,
Cookies-shm, Local State, Session descendants, a newly created profile's
Cookies, Firefox cookies.sqlite, storage descendants and sessionstore-backups.
Symlink, known hardlink, rename, `/proc/PID/fd` and bind-alias regressions also
denied. Owning synthetic browsers remained allowed.

The first external-hardlink investigation honestly found 984/1,000 recoveries.
The repair synchronously checks configured namespaces only when an otherwise
unclassified event inode has `st_nlink > 1`, using directory reads and metadata
without opening regular contents. The final 10,000-iteration rerun had zero
recoveries.

Post-commit review identified a separate nlink=1 rename-away gap: structural
path classification protected one open but did not retain the new inode. The
Phase 19.1 fix promotes the inode before answering the permission event. Root
case A (owning browser first open, then rename-away) and case B (denied first
open, then rename-away retry) both recovered zero objects. Case C moved an
inode into and out of a sensitive name without opening it there; the later
external open succeeded. This is explicitly the open-only `FAN_OPEN_PERM`
boundary, not a claimed rename guarantee.

Browser adversarial acceptance passed in both modes:

```text
PASS=24 FAIL=0 BLOCKED=0
desktop delivered 15/15 audited DENY notifications to mako
```

That suite proved ordinary read, mmap, SQLite, copy, symlink, hardlink, child,
Firefox Cookie SQLite, Session Store, rename, `/proc/PID/fd`, replacement,
nested resource and local AF_UNIX canary-transfer denial. Enrolled positive
controls recovered their own synthetic canaries. Audit and daemon logs held
metadata only.

## SSH broker trust chain

```text
explicit user action
  -> guardctl forks a child and stops it before exec
  -> guardd authenticates the IPC peer with SO_PEERCRED
  -> PID/PPID/UID/GID/stop-state/start-time verified from /proc
  -> real polkit authorization for the kernel-bound process subject
  -> all child facts rechecked
  -> daemon-selected root-owned, non-writable absolute /usr/bin/ssh-add
  -> SSH_AUTH_SOCK inode/owner and connected peer SO_PEERCRED
  -> root-owned, non-writable system ssh-agent stable identity
  -> verified agent socket inode pinned below root-controlled directory
  -> child receives only the pin and a minimal execve environment
  -> 30-second one-shot SshLoadLease bound to stable ssh-add + pin
  -> first matching private-key open ALLOW_BY_LEASE and consumes lease
  -> ssh-add transfers key to the already-verified ssh-agent
  -> second/expired/post-exit/wrong-endpoint opens DENY
```

The exec environment contains only pinned `SSH_AUTH_SOCK` and `LC_ALL=C`.
`PATH`, HOME, loader variables, askpass variables and caller injection state are
not inherited. The daemon verifies live `ssh-add` environment against the pin
on the FAN_OPEN_PERM path. It never trusts a client-declared process identity,
socket pathname, socket filename, or process name alone.

The 29-case SSH broker adversarial suite passed in both conservative and
Strict Mode. A real ephemeral key appeared in `ssh-add -l`; a fake same-UID
agent, post-authorization replacement listeners and a client ignoring the pin
received zero key bytes. One-shot, second-open, timeout, disconnect, fake
executable, hostile `LD_PRELOAD` and secret scan cases passed.

## Performance and queue health

| Workload | No guard | Conservative | Strict | Strict overhead |
| --- | ---: | ---: | ---: | ---: |
| 100,000 unprotected opens | 111.059 ms | 111.212 ms | 1377.815 ms | 12.41x |
| 10,000 owning-browser opens | 14.933 ms | 316.735 ms | 293.716 ms | 19.67x |
| 2,000 would-be denied opens | 2.048 ms allowed | 62.860 ms denied | 62.652 ms denied | 30.60x |

Strict ordinary throughput was 72,578 opens/s. Denied latency was
29.6/36.6/58.3/283.7 microseconds p50/p95/p99/max. This cost is material but
the host remained usable; Strict stays opt-in. `/usr/bin/time` was unavailable,
so CPU percentage was not separately captured; wall time, throughput and
latency were measured.

The bounded concurrent run observed:

```text
events:               180624
fast unrelated/self:  160324
protected events:      20300
fanotify overflows:        0
audit drops:               0
classifier failures:      0
topology degraded:     false
```

No unlimited queue is requested. Any observed future overflow or classifier
failure makes status DEGRADED.

Phase 19.1 also forced 16,000 exceptional hardlink-alias namespace scans with
eight concurrent readers. The synthetic workload completed in 889 ms with zero
queue overflow, classifier failure, or audit drop. This is a targeted bounded
measurement, not a denial-of-service resistance guarantee for arbitrary real
profile sizes.

## Privileged acceptance

| Suite | PASS | FAIL | BLOCKED |
| --- | ---: | ---: | ---: |
| `test-fanotify-root.sh` | 6 | 0 | 0 |
| `test-browser-enforcement-root.sh` | 14 | 0 | 0 |
| `test-ssh-enforcement-root.sh` | 17 | 0 | 0 |
| `test-bypass-root.sh` | 18 | 0 | 2 |
| `test-ssh-load-root.sh` | 10 | 0 | 0 |
| `test-systemd-root.sh` | 13 | 0 | 0 |
| `test-agent-compat-root.sh` | 9 | 0 | 0 |
| `test-hardening-root.sh` | 1 | 0 | 0 |
| browser adversarial, conservative | 24 | 0 | 0 |
| browser adversarial, Strict | 24 | 0 | 0 |
| SSH broker adversarial, conservative | 29 | 0 | 0 |
| SSH broker adversarial, Strict | 29 | 0 | 0 |
| `test-installed-auth-root.sh` | 14 | 0 | 1 |
| `test-strict-filesystem-root.sh` | 25 | 0 | 0 |
| `test-strict-concurrency-root.sh` | 1 | 0 | 0 |
| `benchmark-strict-filesystem-root.sh` | 1 | 0 | 0 |
| topology stress, conservative | 1 | 0 | 0 |
| topology stress, Strict | 2 | 0 | 0 |

The current Strict filesystem suite also reported one separate `OBSERVED`
boundary: rename into and out of a sensitive pathname without any intervening
open was not mediated. It is not counted as PASS, FAIL, or BLOCKED because it
is an explicit measurement of the open-only backend rather than an access
decision test.

The bypass BLOCKED rows are the explicit pre-open/inherited-fd non-goals. The
installed-auth BLOCKED row is an already-running user manager with stale
supplementary groups; real polkit denial/authorization passed, and the
installed notifier delivered to mako in a fresh group context. No mandatory
suite had a FAIL.

Systemd tests observed stop fail-open, restart reconstruction, automatic
recovery after `SIGKILL`, stale-socket recovery and journal secret scan.
Installed tests observed socket ownership/mode, own-UID queries, cross-UID
denial, real polkit NO/YES, non-root broker load and notification delivery.

## Rust quality gates

```text
cargo fmt --check                                           PASS
cargo clippy --workspace --all-targets --all-features
  -- -D warnings                                            PASS
cargo test --workspace --all-features                       201 passed, 0 failed
cargo build --release                                       PASS
```

## Remaining known gaps / non-goals

1. Root or kernel compromise can kill guardd or bypass fanotify.
2. Browser extensions, injection and remote debugging inside an authorized
   browser are not mediated.
3. Pre-open and inherited descriptors are not retroactively intercepted;
   filesystem-wide `FAN_ACCESS_PERM` remains out of scope.
4. Daemon death closes the fanotify group and is fail-open until systemd
   restores it (two seconds in the tested unit).
5. Conservative mode retains its topology race. Only Strict is promoted.
6. MigrationAccessLease is process-tree scoped but not read-only because the
   Linux fanotify event fd does not expose original open flags.
7. An already-unlocked ssh-agent can still be abused for signatures by a
   same-UID process; this firewall protects raw private-key files.
8. Runtime-only SSH enrollment on a previously unmarked filesystem does not
   create a new persistent Strict namespace.
9. The tested bind alias denied. Disposable tmpfs unmount/reappearance was
   detected and status became DEGRADED, but the reappeared filesystem is not
   automatically re-marked; restart is required. Exotic mount namespaces were
   not exhaustively covered.
10. Strict has material open overhead and a finite kernel event queue. The
    observed acceptance load did not overflow it; that is not a proof against
    arbitrary resource-exhaustion attacks.
11. `FAN_OPEN_PERM` does not observe rename itself. An inode moved through a
    sensitive pathname and back out without any open while sensitive is not
    labeled. If browser data were written through a descriptor opened before
    that transit, it would also fall under the existing pre-open-fd non-goal.

## Promotion rationale

All mandatory suites actually ran with zero FAIL. Strict immediate replacement,
new nested resources, new profile resources and the repaired hardlink alias had
zero canary recoveries. Browser and SSH adversarial suites stayed green in
Strict Mode; secret scans, systemd recovery, real polkit, notification delivery
and queue health passed. No guarantee is stated more strongly than the tested
fanotify backend supports.

```text
SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST
```
