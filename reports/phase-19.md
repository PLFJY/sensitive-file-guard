# Phase 19 — Strict Filesystem Enforcement and Performance Acceptance

> Post-commit review found a structural-hit rename-away gap. Phase 19.1 fixed
> it and added root A/B/C plus alias-scan amplification coverage. See
> [`phase-19.1.md`](phase-19.1.md). The measurements below remain the original
> Phase 19 evidence rather than being silently rewritten.

## Decision

```text
SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST
```

This promotion applies only to explicit `strict-filesystem` configuration.
Conservative mode remains available and retains its measured first-open race.
Every result below is from an observed execution on the target host, not from
the existence of a script. All fixtures were disposable and synthetic. No real
profile, Cookie, token, password, SSH key, or public network was used.

## Host

| Component | Observed value |
| --- | --- |
| OS | Arch Linux x86_64 |
| Kernel | `7.1.6-arch1-1` |
| systemd | `261.2-1` |
| OpenSSH | `10.4p1-3` |
| polkit | `127-3` |
| Rust | `rustc 1.97.0 (2d8144b78 2026-07-07)` |
| Cargo | `1.97.0 (c980f4866 2026-06-30)` |
| Race/strict fixture filesystem | `/tmp` tmpfs |
| Performance filesystem | ext4 (`/dev/nvme0n1p3`) |
| Relevant policy | `fs.protected_hardlinks=1`, `kernel.yama.ptrace_scope=1` |
| Base commit | `5159c1c` plus this Phase 19 worktree |

## Backend implementation

The config now selects one explicit mode:

```text
conservative
strict-filesystem
```

Conservative preserves the existing object and recursive directory marks plus
inotify rediscovery. Strict deduplicates all configured browser roots and SSH
keys by `st_dev`, then installs `FAN_MARK_FILESYSTEM | FAN_OPEN_PERM` for every
required filesystem. A failed/missing required root or filesystem mark aborts
startup; guardd does not print ACTIVE.
Status also compares the required count with live kernel `fanotify sdev:`
entries from the group fdinfo; a lost mark reports unhealthy/DEGRADED.

Strict event classification is:

```text
known (dev, ino)
  -> protected
else structural path under configured namespace
  -> protected
else st_nlink > 1 and protected-namespace alias exists
  -> protected and index inode
else
  -> immediate unrelated allow
```

Unrelated opens do not resolve ancestry, hash executables, query packages or
SQLite, or create audit records. Browser path intent covers Chromium Local
State, Cookies variants, Login/Web Data, Sessions, Session Storage, Local
Storage and IndexedDB; Firefox covers cookies variants, logins/key material,
sessionstore-backups and storage. Inotify remains metadata/index maintenance,
not the Strict security boundary.

### Self-event safety

The audit store is opened before filesystem marks. Kernel-reported guardd PID
events take an allow path before the engine mutex. The topology thread can
refresh metadata without installing redundant object marks in Strict Mode.
Startup, audit writes, resource refresh, new topology, IPC status/event reads,
concurrent workload and clean shutdown all completed without a deadlock.

### Hardlink alias repair

The first targeted run exposed a real gap:

```text
new inode staged outside profile
hardlink external alias
rename inode over Cookies
immediately open external alias

iterations: 1000
successful unauthorized reads: 984
denied: 16
```

An event fd opened through a hardlink exposes that alias, not every inode name.
The repair limits extra work to `st_nlink > 1`: guardd performs a metadata-only
search of configured namespaces and compares dev/inode before allowing. It
does not open regular-file contents. Final observed result:

```text
iterations: 10000
successful unauthorized reads: 0
denied: 10000
other errors: 0
```

## Security result

| Mode | Iterations | Successful unauthorized reads | Denied | Other errors |
| --- | ---: | ---: | ---: | ---: |
| Conservative, Phase 19 rerun | 10,000 | 10,000 | 0 | 0 |
| Strict Filesystem | 10,000 | 0 | 10,000 | 0 |
| Strict external-hardlink replacement | 10,000 | 0 | 10,000 | 0 |

The historical Phase 18 conservative result remains recorded:

```text
10,000 / 10,000 immediate reads succeeded
convergence p50/p95/p99/max: 1171/2225/2347/4039 us
```

The Phase 19 conservative rerun converged at
1178/2205/2331/3412 microseconds. Strict requires no convergence wait and has
no time-to-protection distribution: all first attempts were permission-denied.

`test-strict-filesystem-root.sh` produced `PASS=22 FAIL=0 BLOCKED=0`. It proved
first-attempt denial for Chromium Network/Cookies, Cookies-wal, Cookies-shm,
Local State, a Session descendant, a new profile's Cookies, Firefox
cookies.sqlite, a storage descendant and a sessionstore descendant. It also
re-ran symlink, known hardlink, rename and `/proc/PID/fd`, allowed an owning
browser, tested a bind alias, scanned audit/log content, exercised clean
shutdown, proved missing-root startup fails closed, and unmounted/remounted a
disposable tmpfs. The kernel fdinfo count fell from one to zero and status
changed from ACTIVE/healthy to DEGRADED/unhealthy rather than silently claiming
the new filesystem was protected.

The existing browser adversarial suite passed in both modes. Each run was
`PASS=24 FAIL=0 BLOCKED=0`; mako received 15/15 audited DENY notifications.
The complete 29-case SSH broker suite also passed in both conservative and
Strict Mode, including fake agent, live socket binding, one-shot consumption,
expiry, environment sanitation and secret-content scan.

## Performance

The benchmark uses aggregate open counts and never prints file contents.

| Workload | No guard | Conservative | Strict | Strict overhead vs absent |
| --- | ---: | ---: | ---: | ---: |
| 100,000 unprotected opens on marked ext4 | 111.059 ms / 900,425 ops/s | 111.212 ms / 899,181 ops/s | 1377.815 ms / 72,578 ops/s | 12.41x |
| 10,000 owning-browser protected opens | 14.933 ms / 669,654 ops/s | 316.735 ms / 31,572 ops/s | 293.716 ms / 34,046 ops/s | 19.67x |
| 2,000 unauthorized protected opens | 2.048 ms / 976,770 ops/s (allowed control) | 62.860 ms / 31,816 denies/s | 62.652 ms / 31,922 denies/s | 30.60x |

Strict denied-open latency was p50/p95/p99/max
29.6/36.6/58.3/283.7 microseconds. Strict unprotected-open latency was
12.2/16.8/27.3/485.0 microseconds. The cached `cargo check` smoke timings were
0.126943s absent, 0.060658s conservative and 0.078602s strict; these tiny runs
are dominated by warm-cache/order noise, but did not indicate an unusable
machine. `/usr/bin/time` was not installed on the host, so CPU percentage was
not recorded separately; wall time, throughput, and latency were recorded.
The raw-open overhead is material, so Strict remains opt-in.

## Queue and concurrency health

The bounded concurrent test combined eight unrelated readers, four owning
browser readers, two unauthorized readers, an immediate replacement loop,
200 status queries and 200 event queries:

```text
strict events:        180624
strict fast allowed:  160324
protected events:      20300
policy allowed:         20000
policy denied:            300
fanotify overflows:          0
audit drops:                 0
classifier failures:        0
topology degraded:       false
```

The separate performance run processed 113,093 strict events with zero
overflow, audit drop or classifier failure. guardd does not request
`FAN_UNLIMITED_QUEUE`; any future overflow increments a counter and makes
status DEGRADED.

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
| `test-browser-adversarial-root.sh` conservative | 24 | 0 | 0 |
| `test-browser-adversarial-root.sh` strict | 24 | 0 | 0 |
| `test-ssh-broker-adversarial-root.sh` conservative | 29 | 0 | 0 |
| `test-ssh-broker-adversarial-root.sh` strict | 29 | 0 | 0 |
| `test-installed-auth-root.sh` | 14 | 0 | 1 |
| `test-strict-filesystem-root.sh` | 22 | 0 | 0 |
| `test-strict-concurrency-root.sh` | 1 | 0 | 0 |
| `benchmark-strict-filesystem-root.sh` | 1 | 0 | 0 |
| topology stress, conservative | 1 | 0 | 0 |
| topology stress, strict | 2 | 0 | 0 |

The two bypass BLOCKED cases are pre-open and inherited pre-open descriptors,
explicit V1 non-goals. The installed-auth BLOCKED case is the already-running
user manager's stale supplementary groups after installation. Real polkit
deny and allow passed; the installed notifier delivered to mako from a fresh
group context. These are non-essential to the Strict first-open invariant and
are not hidden as PASS.

The systemd suite observed service stop fail-open, mark reconstruction,
automatic restart after `SIGKILL`, stale-socket recovery and journal secret
scan. The installed suite observed `0660 root:guardd-users`, own-UID event
filtering, cross-UID denial, real polkit NO/YES, non-root SSH broker load and
desktop delivery.

## Rust gates

```text
cargo fmt --check                                           PASS
cargo clippy --workspace --all-targets --all-features
  -- -D warnings                                            PASS
cargo test --workspace --all-features                       198 passed, 0 failed
cargo build --release                                       PASS
```

The first sandboxed test attempt could not bind two local Unix test sockets
(`EPERM`). The exact full command was rerun outside that sandbox and all 200
tests passed; the blocked attempt is not presented as a test failure repair.

## Remaining known gaps and non-goals

1. Root/kernel compromise can kill guardd, remove marks, or bypass the hook.
2. Malicious browser extensions, browser injection and remote debugging run
   inside an authorized browser identity and are out of scope.
3. Pre-open and inherited descriptors are not retroactively mediated;
   filesystem-wide `FAN_ACCESS_PERM` was deliberately not added.
4. Closing/crashing guardd removes the fanotify group and creates a fail-open
   interval; the tested systemd unit restored enforcement after its configured
   two-second restart delay.
5. Conservative mode retains the measured topology race. Strict does not use
   inotify as the first-open security boundary for known sensitive namespaces.
6. MigrationAccessLease is process-tree scoped but is not read-only: fanotify
   event fd flags do not reveal the original opener mode.
7. Once a key is loaded, same-UID misuse of already-unlocked ssh-agent signing
   authority is outside this raw-key firewall.
8. Runtime-only SSH enrollment on a previously unmarked filesystem does not
   dynamically create a persistent Strict namespace.
9. The tested bind alias of an indexed inode denied. Disposable tmpfs
   unmount/reappearance was detected as DEGRADED but does not automatically
   re-mark the new filesystem; restart is required. Exotic mount namespaces
   were not exhaustively exercised, and mount creation requires privilege
   outside the unprivileged-attacker model.
10. Strict ordinary-open overhead is material, and finite fanotify queues can
    still be exhausted by loads beyond the observed acceptance envelope.

## Final decision

All Phase 19 promotion criteria were observed with zero mandatory FAIL:
replacement and new-resource first opens recovered no canary, browser and SSH
adversarial suites remained green in Strict Mode, queue/audit health remained
green, logs contained no secret content, and real systemd/polkit/notification
paths passed. The measured performance cost keeps Strict opt-in but did not
make the tested host unusable.

```text
SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST
```
