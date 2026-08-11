# Phase 18 — Linux V1 Security Hardening Pass 2

## Status

**IMPLEMENTED AND EXECUTED ON THE TARGET ARCH HOST. SECURITY ACCEPTANCE
REMAINS PENDING.**

The SSH broker, installed IPC/polkit path, systemd recovery, and existing
steady-state browser enforcement all passed. The new topology stress test also
proved that the documented conservative inotify-to-fanotify interval is
reliably readable on this host. That observed browser-data gap prevents an
honest security-accepted promotion.

All fixtures were generated below unique `/tmp/guard-*` directories. No real
browser profile, Cookie, token, password, private key, or public network was
used.

## Host under test

| Component | Observed value |
| --- | --- |
| OS | Arch Linux x86_64 |
| Kernel | `7.1.6-arch1-1` |
| systemd | `261.2-1` |
| OpenSSH | `10.4p1-3` |
| polkit | `127-3` |
| Rust | `rustc 1.97.0 (2d8144b78 2026-07-07)` |
| Cargo | `1.97.0 (c980f4866 2026-06-30)` |
| Test filesystem | `/tmp` on `tmpfs` (`nosuid,nodev`) |
| Relevant sysctls | `fs.protected_hardlinks=1`, `kernel.yama.ptrace_scope=1` |
| Base commit | `b54116158c0a` |

## SSH broker hardening

The broker now establishes this trust chain:

```text
explicit guardctl ssh load
  -> SO_PEERCRED-bound IPC peer
  -> direct child stopped before exec
  -> child PID/PPID/UID/GID/start-time rechecked around polkit
  -> daemon-selected root-owned, non-writable /usr/bin/ssh-add identity
  -> SSH_AUTH_SOCK inode + owner checked
  -> connected peer SO_PEERCRED checked
  -> peer PID/start-time/exe dev+inode checked against system ssh-agent
  -> verified socket inode hardlinked into a root-controlled directory
  -> 30-second one-shot SshLoadLease
  -> child receives only the pinned path and execve's absolute ssh-add
  -> FAN_OPEN_PERM verifies live ssh-add SSH_AUTH_SOCK equals that pin
  -> first protected-key open AllowByLease; later opens deny
```

The hardlink pin closes the check/use gap where the user-controlled original
`SSH_AUTH_SOCK` pathname could be replaced after authorization. The successful
adversarial test replaced that pathname with a same-UID fake listener after
authorization; `ssh-add` still reached the preverified OpenSSH agent and the
fake listener received zero bytes. A second, non-cooperative client ignored the
returned pin and resumed real system `ssh-add` with the replaced pathname; the
hot-path environment binding denied the key open, both fake and trusted agents
remained empty, and no private-key bytes escaped.

The stopped child gets an exact two-entry environment:

```text
SSH_AUTH_SOCK=<daemon-created pinned socket path>
LC_ALL=C
```

It does not inherit `PATH`, `HOME`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
`LD_DEBUG`, `LD_PROFILE`, `GLIBC_TUNABLES`, `SSH_ASKPASS`, or the caller's
remaining environment. A real shared-object constructor test observed the
hostile `LD_PRELOAD` in `guardctl` once and not in brokered `ssh-add`.

### Stopped-child protocol review

| Case | Final behavior / evidence |
| --- | --- |
| PID reuse or killed child/PID replacement | child PID, start token, PPID, UID/GID and stop state are sampled before and after polkit; any change rejects; lease identity also includes the original start token |
| Child exits before authorization | `/proc` verification fails closed; no lease is published |
| Wrong parent, UID/GID, or running child | rejected by kernel-observed child verification; privileged wrong-parent/running cases and UID/GID unit regression pass |
| Altered request or user-writable/fake `ssh-add` | client identity fields are absent/ignored; only daemon-selected root-owned non-writable system `ssh-add` can match the lease |
| Another process attempts reuse | stable identity mismatch denies; PID alone is insufficient |
| Second open by the same process | first allow atomically marks the lease used; second open denies |
| Process exit or timeout | guardctl revokes after wait; abandoned lease expires after 30 seconds; both cases were observed denied |
| IPC disconnect | connection hangup cancels pending authorization; response-write failure revokes a newly created capability; adversarial disconnect left no live lease |
| Polkit denial | real polkit NO rule prevented mutation/load capability creation |
| Invalid or swapped agent | fake executable listener rejects; cooperative swap uses immutable pin; non-cooperative swap is denied by live-environment binding |
| Daemon restart during load | leases are memory-only and disappear on restart, but daemon death also closes fanotify marks; the documented two-second fail-open window still applies. After restart, the systemd suite observed marks rebuilt and raw access denied |

The daemon-restart row is not presented as fail-closed: a child resumed while
guardd is actually down is covered by the general daemon-crash limitation and
cannot be fixed by a userspace lease check.

The installed unit needs the following narrowly documented capabilities in
addition to fanotify's `CAP_SYS_ADMIN`: `CAP_SYS_PTRACE` to resolve another
UID's `/proc/<pid>/exe` on the tested hardened kernel, `CAP_DAC_READ_SEARCH`
and `CAP_DAC_OVERRIDE` to inspect/connect owner-only agent sockets,
`CAP_FOWNER` to pin a user-owned socket with `fs.protected_hardlinks=1`, and
`CAP_KILL` for stopped-child lifecycle handling.

## IPC mutation authorization review

| Operation | Who may invoke | Kernel-derived trust | Client input independently verified | Capability / lifetime | Polkit |
| --- | --- | --- | --- | --- | --- |
| `MigrationAuthorize` | socket peer for its own UID | IPC PID/UID/GID from `SO_PEERCRED`; peer start time remains live during authorization | source browser/profile and target browser must resolve to enrolled config and daemon-known executable identity; duration is capped | armed capability binds on first matching access to one exact process tree; expiry/revoke/root exit kills it | required for non-root |
| `SshProtect` | root or owner of the candidate file | IPC credentials from `SO_PEERCRED`; owner UID from `stat` | canonical regular-file candidate, owner, reserved/public-key names, and kernel mark success are checked before registry publication | adds runtime protection; does not authorize reading | required for non-root |
| `SshLoadAuthorize` | owner of an already-protected key using the broker flow | IPC credentials; stopped child facts; agent socket peer credentials; child/agent stable process identities | key owner/resource, direct stopped child, trusted system `ssh-add`, socket inode/owner, trusted system `ssh-agent`, and all facts again after authorization | exactly one matching key open, 30 seconds, then used/revoked/expired | required for non-root |
| `LeasesRevoke` | lease owner or root | IPC UID from `SO_PEERCRED`; lease owner from daemon state | opaque lease ID is matched only within daemon state | removes capability immediately and removes any agent pin | no; revocation reduces privilege, and cross-user revocation is denied |

`pkcheck` uses a PID,start-time,UID process subject and its supported
`-d KEY VALUE` detail form. While an interactive decision is pending, guardd
rechecks the peer start token every 50ms and cancels if the IPC client exits or
the PID is reused. It also polls the accepted Unix connection for hangup and
revokes a capability if its response cannot be delivered. The observed
installed test used the real polkit daemon and temporary allow/deny rules; no
authorization result was mocked.

## Observed privileged acceptance

The scripts ran as real UID 0 through the host's `pkexec` authorization path
(the non-interactive agent could not type into `sudo`); each script retained
its own `id -u`/capability precondition. They were not syntax-only runs.

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
| `test-browser-adversarial-root.sh` | 24 | 0 | 0 |
| `test-ssh-broker-adversarial-root.sh` | 29 | 0 | 0 |
| `test-topology-race-stress-root.sh` | 1 | 0 | 0 |
| `test-installed-auth-root.sh` | 14 | 0 | 1 |

The two bypass BLOCKED rows are the explicitly out-of-scope pre-open and
inherited pre-open file-descriptor cases. The installed-auth BLOCKED row is a
host session-lifecycle condition: the already-running `systemd --user` manager
predated the installer's addition of the user to `guardd-users`. The installed
unit was active; a fresh process with the new supplementary group used the
installed `guard-notify` binary and delivered the DENY to mako. A logout/login
is required to refresh the existing user manager. Separately, the browser
adversarial suite delivered all 15/15 audited DENY notifications to mako.

The systemd suite observed stop as fail-open, restart reconstruction, and
automatic recovery after `SIGKILL`; enforcement was restored after the
configured two-second `RestartSec` interval. Journal and SQLite scans contained
decision metadata but no synthetic canary or private-key bytes.

## Browser adversarial evidence

The previously observed and re-run suite remained:

```text
Defensive adversarial summary: PASS=24 FAIL=0 BLOCKED=0
desktop delivered 15/15 audited DENY notifications
```

This proves steady-state denial for direct read, mmap, SQLite, copy, symlink,
hardlink, child, Firefox Cookie SQLite, Session Store, rename, `/proc/PID/fd`,
and local AF_UNIX canary transfer. It also proves eventual protection of a
replacement Cookie inode and a new nested Session resource. It does not prove
that the interval before rediscovery is unreadable.

## Topology race measurement

The synthetic stress probe repeatedly created a new inode, atomically renamed
it over Chromium `Cookies`, and immediately attempted an unauthorized read:

```text
iterations:                    10000
successful unauthorized reads: 10000
denied immediate reads:        0
other errors:                  0
time-to-protection samples:    10000
p50 / p95 / p99 / max:         1171 / 2225 / 2347 / 4039 microseconds
final inode convergence:       PASS
```

This is an empirical result on tmpfs, not a race-free guarantee and not an
enforcement PASS. The existing conservative mode converges, but its replacement
window is reproducibly exploitable. Before promotion, a Strict Mode should use
`FAN_MARK_FILESYSTEM` permission monitoring and allow unrelated filesystem
objects only after userspace resource classification. It needs a workload
benchmark and queue-overflow test because filesystem-scope monitoring broadens
the hot path substantially. Strict Mode was not improvised during this pass.

## Normal quality gates

Observed after the final code changes:

```text
cargo fmt --check                                           PASS
cargo clippy --workspace --all-targets --all-features
  -- -D warnings                                            PASS
cargo test --workspace --all-features                       193 passed, 0 failed
cargo build --release                                       PASS
```

## Decision

`SECURITY ACCEPTANCE PENDING`

The mandatory steady-state and broker suites are green, but a repeatable
browser authentication-data read exists during every tested replacement inode
transition. Calling that security-accepted would make the documented guarantee
stronger than the backend result. Promotion requires a strict filesystem-scope
mode (or another kernel boundary) that closes this measured gap and passes the
same stress/privileged suites; a fresh login should also clear the one
installed-notifier session BLOCKED row.
