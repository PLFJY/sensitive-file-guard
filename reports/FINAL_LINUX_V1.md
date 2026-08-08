# Linux V1 Acceptance Report

**Status: SECURITY ACCEPTANCE PENDING**

Hardening Pass 2 and every required privileged suite were actually executed
on the target Arch Linux host. Steady-state browser enforcement, the hardened
SSH broker, real systemd recovery, real polkit decisions, audit-content scans,
and desktop notification delivery passed. Promotion is withheld because the
new 10,000-iteration stress test recovered a synthetic Cookie canary in every
immediate atomic-replacement attempt before the inotify rediscovery path
installed a new inode mark.

No real browser data or SSH key was accessed. All privileged tests used unique
disposable profiles, ephemeral keys/agents, synthetic canaries, and local-only
AF_UNIX sinks.

## Tested host

| Component | Observed value |
| --- | --- |
| Distribution | Arch Linux x86_64 |
| Kernel | `7.1.6-arch1-1` |
| systemd | `261.2-1` |
| OpenSSH | `10.4p1-3` |
| polkit | `127-3` |
| Rust | `rustc 1.97.0 (2d8144b78 2026-07-07)` |
| Cargo | `1.97.0 (c980f4866 2026-06-30)` |
| Test filesystem | `/tmp` on `tmpfs` (`nosuid,nodev`) |
| Relevant host policy | `fs.protected_hardlinks=1`, `kernel.yama.ptrace_scope=1` |
| Base commit | `b54116158c0a` plus this uncommitted hardening pass |

## Implemented architecture

```text
guardctl / guard-tui                 guard-notify (user session)
          |                                      |
          +---------- Unix IPC / SO_PEERCRED ----+
                             |
                         guardd (root)
              policy / identity / leases / polkit
                  resource registry / audit
                             |
                    fanotify FAN_OPEN_PERM
                             |
                    protected local objects
```

`guardd` owns the security boundary. The socket is `0660
root:guardd-users`; group membership grants transport, not mutation authority.
Non-root security mutations use polkit. `guard-notify` has no policy engine and
only presents the requesting UID's filtered audit records inside that user's
desktop session.

## Hardening Pass 2

### Authoritative SSH agent verification

`guardd` no longer accepts mere socket existence/type/ownership as proof of a
trusted agent. It connects to the endpoint with a bounded timeout, obtains the
server's kernel credentials through `SO_PEERCRED`, and verifies that PID's UID,
start time, canonical executable, and executable dev/inode against the
root-owned, non-group/other-writable system OpenSSH `ssh-agent`.

The daemon verifies both the stopped `ssh-add` child and agent before and after
polkit. It then hardlinks the verified Unix-socket inode below a root-owned,
non-writable same-filesystem directory and gives only that pinned path to the
child. Replacing the original `SSH_AUTH_SOCK` pathname after approval therefore
cannot redirect `ssh-add` to a malicious listener.

The installed service explicitly retains only the capabilities required by
the observed kernel operations: `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_KILL`,
`CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, and `CAP_FOWNER`. `PrivateTmp=false`
is required because OpenSSH commonly creates the user's agent endpoint below
`/tmp`; pathname text is never the trust decision.

### Broker child and environment

`guardctl` forks one child, stops it before exec, and sends only its PID. The
daemon derives PID/PPID/UID/GID/start time itself, selects the trusted absolute
`/usr/bin/ssh-add`, and rejects a non-child, running child, wrong credentials,
PID reuse, or a changed child after interactive authorization. The peer's own
start token and accepted IPC connection are monitored while `pkcheck` runs, so
disconnect/exit/PID reuse cancels the authorization. If a capability response
cannot be delivered, the capability is revoked.

After approval, the child receives the daemon-pinned socket over a private pipe
and uses `execve` with only `SSH_AUTH_SOCK=<pinned>` and `LC_ALL=C`. It does not
inherit loader or askpass injection variables. The 30-second lease is bound to
the future system `ssh-add` stable identity, the exact pinned endpoint observed
again from the live process environment on `FAN_OPEN_PERM`, and exactly one
private-key open. Thus a malicious parent cannot ignore the daemon response and
resume genuine `ssh-add` against a swapped agent path.

### Migration and IPC semantics

Linux still exposes `MigrationAccessLease`, not a read-only guarantee. An
armed lease binds on first matching access to one exact process tree and dies
on root exit/PID reuse/revoke/expiry. `MigrationAuthorize`, `SshProtect`, and
`SshLoadAuthorize` require real polkit for non-root callers. `LeasesRevoke`
intentionally requires only lease ownership (or root): revocation reduces
privilege, and cross-UID revocation is denied.

## Actual acceptance results

The scripts ran as real UID 0 through the host's `pkexec` authorization path;
they were not mocked or syntax-only executions.

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

All table rows are observed executions, not script-existence claims. The two
bypass BLOCKED rows are the documented pre-open and inherited-pre-open fd
limits. The installed-auth BLOCKED row is the already-running user systemd
manager's stale supplementary-group list after installation; the user service
was active, and the installed presenter delivered to mako when launched with a
fresh group context. A logout/login is required after installation.

The browser adversarial result remained:

```text
PASS=24 FAIL=0 BLOCKED=0
desktop delivered 15/15 audited DENY notifications
```

It demonstrated denial with audit proof for ordinary read, mmap, SQLite,
copy/read, symlink, hardlink, child, Firefox cookies, sessions, renamed inode,
`/proc/PID/fd`, and two local-only synthetic exfiltration probes. Enrolled
positive controls recovered/transmitted their own canaries. Audit and daemon
logs contained metadata only.

The SSH broker suite demonstrated direct/copy/Python/Rust denial, public-key
allow, stopped-child rejection cases, untrusted executable rejection, hostile
environment removal, a real ephemeral key visible through `ssh-add -l`, one
`AllowByLease`, second-open/expiry/post-exit/disconnected-client denial, and
zero key bytes received by a same-UID fake agent, a cooperative pathname
replacement listener, and a non-cooperative client that deliberately ignored
the returned pinned path.

The installed suite observed the real `0660 root:guardd-users` socket, per-UID
event filtering, real polkit NO and YES decisions, owner-only mutation,
non-root brokered load, user-session service activation, and mako delivery. No
socket was loosened to `0666`, and polkit was not mocked.

The systemd suite observed fail-open after service stop, reconstructed marks on
start, automatic recovery after daemon `SIGKILL`, stale-socket recovery, and no
secret bytes in journald.

## Browser topology race

On `/tmp` tmpfs, the new probe performed 10,000 iterations of:

```text
create fresh synthetic Cookie inode
atomic rename over Cookies
immediate unauthorized read
wait until fanotify protection converges
```

Observed:

```text
successful unauthorized reads: 10000 / 10000
denied immediate reads:        0 / 10000
other errors:                  0
time-to-protection p50:        1171 us
time-to-protection p95:        2225 us
time-to-protection p99:        2347 us
time-to-protection max:        4039 us
final convergence:             PASS
```

The older replacement-inode tests correctly prove eventual rediscovery; they
do not contradict this measurement. Conservative mode is not race-free. A
promotion candidate needs a benchmarked Strict Mode using
`FAN_MARK_FILESYSTEM` (or an equivalent kernel boundary) so the permission
event occurs before an open of a newly replaced protected pathname succeeds.

## Quality gates

```text
cargo fmt --check                                           PASS
cargo clippy --workspace --all-targets --all-features
  -- -D warnings                                            PASS
cargo test --workspace --all-features                       195 passed, 0 failed
cargo build --release                                       PASS
```

## Remaining known gaps

1. A root/kernel compromise can kill or bypass the daemon and is out of scope.
2. Browser extensions, process injection, and remote-debugging abuse inside an
   authorized browser are out of scope.
3. File descriptors opened before a mark, including inherited fds, are not
   retroactively mediated by `FAN_OPEN_PERM`.
4. Daemon exit closes the fanotify group and causes a fail-open interval; the
   tested unit restores enforcement after its two-second restart delay.
5. The conservative topology watcher has the measured, reproducible
   replacement-inode window above.
6. Migration access is process-tree scoped but not read-only on this fanotify
   backend.
7. After a key is loaded, already-unlocked ssh-agent signing-authority abuse by
   a same-UID process is outside this raw-file firewall. Agent confirmation and
   lifetime constraints remain the user's mitigation.
8. Runtime-only SSH enrollment does not add a new persistent topology watch
   root; replace-and-reprotect is required unless the parent is already watched.

## Final decision

```text
SECURITY ACCEPTANCE PENDING
```

The SSH hardening and full privileged execution objectives are complete, but
the measured browser replacement window violates the intended “unauthorized
probe cannot recover the canary” success condition. Linux V1 must not be
advertised for real secrets until a strict replacement-safe mode closes that
gap and passes the same stress and privileged suites.
