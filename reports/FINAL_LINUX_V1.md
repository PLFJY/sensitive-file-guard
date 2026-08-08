# Linux V1 Acceptance Report

**Status: IMPLEMENTATION COMPLETE ALPHA — SECURITY ACCEPTANCE PENDING**

- Non-privileged quality gates: PASS
- Privileged fanotify/systemd acceptance: **PENDING / NOT RUN in this environment**
- Approval for real Cookie/SSH-key use: **NO**

Latest non-privileged run: **182 tests passed, 0 failed**, plus clean fmt and
clippy with warnings denied.

This status replaces the earlier `COMPLETE` claim. A test script existing in
the repository is not evidence that the script ran.

## Implemented architecture

```text
guardctl / guard-tui                 guard-notify (user session)
          |                                      |
          +---------- Unix IPC / SO_PEERCRED ----+
                             |
                         guardd (root)
                  policy / identity / leases
                  resource registry / audit
                             |
                    fanotify FAN_OPEN_PERM
                             |
                    protected local objects
```

`guardd` owns the security boundary. `guard-notify` contains no policy engine;
it only consumes the requesting UID's filtered audit events and presents them
through the user's desktop session.

## Hardening Pass 1 results

### SSH load authorization

The IPC client no longer declares `ssh-add` path/dev/inode/start-time. It sends
only the PID of a child stopped before `exec`.

Before creating a lease, `guardd` verifies:

1. the PID is a direct child of the kernel-authenticated IPC peer PID;
2. the child is stopped and has the peer's UID/GID;
3. start time comes from `/proc/<pid>/stat`;
4. executable path/dev/inode come from daemon-selected, root-owned system
   `ssh-add`, not from JSON;
5. the inherited `SSH_AUTH_SOCK` is a Unix socket owned by the peer UID;
6. a non-root peer completes the `org.guardd.ssh-load` polkit action, whose
   prompt includes the key path and agent socket.

The resulting lease matches only the post-`exec` system `ssh-add` identity and
is consumed on its first protected-key open. The daemon still does not create
the child itself; this remaining distinction is documented in Phase 16 and
must be exercised in the pending privileged suite before acceptance.

### Dynamic browser resources

An inotify topology watcher starts before initial fanotify marking. Create,
move, delete, and attribute events under enrolled profile roots cause:

- recursive watch rebuild;
- browser resource rediscovery;
- full `(st_dev, st_ino)` index reconstruction;
- fresh critical-file and recursive directory fanotify marks.

This removes the indefinite "unprotected until daemon restart" gap for replaced
Cookie/configured-SSH-key inodes, new sidecars, new profiles, and new tree directories. A bounded
inotify-event → rediscovery → mark race remains. Strict
`FAN_MARK_FILESYSTEM` mode is not implemented.

### Migration access semantics

The Linux backend no longer claims read-only enforcement. The wire response is
`read_only_guaranteed: false`, and the CLI displays that exact limitation.

`MigrationAccessLease` has an explicit lifecycle:

```text
Armed(executable identity)
          |
          | first matching protected access
          v
Bound(root PID + start time + executable identity)
          |
          | exit / PID reuse / revoke / expiry
          v
Dead
```

An armed lease does not directly authorize in the pure policy engine. A bound
lease applies only to the exact root process or an opener whose captured
ancestor chain contains that exact root identity.

### IPC, mutations, and notifications

- Installed socket: `0660 root:guardd-users` via the service's effective group.
- `guardd-users` grants transport access only.
- Migration authorization, SSH protection, and SSH loading require polkit for
  non-root peers.
- `ssh protect` checks file ownership before changing registry state and applies
  the kernel mark before publishing the resource, making the enrollment window
  fail-closed.
- Root `guardd` no longer invokes `notify-send`; `guard-notify` is installed as
  a user service.

## Acceptance matrix

| Area | Non-privileged evidence | Privileged evidence | Status |
| --- | --- | --- | --- |
| Core policy and stable identity | workspace unit tests | root scripts not run | PARTIAL |
| SSH client identity spoof regression | protocol + `/proc` child-verification tests | `test-ssh-load-root.sh` not run | PARTIAL |
| Replacement inode/new profile convergence | inotify unit test | `test-hardening-root.sh` not run | PARTIAL |
| fanotify pre-open denial | parser/engine tests | fanotify scripts not run | PENDING |
| Migration armed→bound tree scope | core + engine tests | browser enforcement script not run | PARTIAL |
| systemd socket group/install/restart | unit/config inspection only | systemd script not run | PENDING |
| User-session notifications | separate presenter builds | desktop-session test not run | PENDING |
| No secret contents in audit | audit/engine tests | root log scan not run | PARTIAL |
| Browser adversarial canary recovery/transmission | transparent probe unit tests | `test-browser-adversarial-root.sh` not run | PARTIAL |

No row that depends on root/CAP_SYS_ADMIN is marked PASS without an observed
run.

## Required privileged acceptance

Run on the intended Arch Linux host, using only the synthetic fixtures created
by the scripts:

```sh
sudo bash scripts/test-fanotify-root.sh
sudo bash scripts/test-browser-enforcement-root.sh
sudo bash scripts/test-ssh-enforcement-root.sh
sudo bash scripts/test-bypass-root.sh
sudo bash scripts/test-ssh-load-root.sh
sudo bash scripts/test-systemd-root.sh
sudo bash scripts/test-agent-compat-root.sh
sudo bash scripts/test-hardening-root.sh
sudo bash scripts/test-browser-adversarial-root.sh
```

Record exact kernel, systemd, polkit, OpenSSH, and package versions and attach
the command output. Any failure keeps the status PENDING; do not downgrade or
disable Secure Boot, SELinux, AppArmor, or other host security to force a pass.

## Remaining known gaps

1. Daemon exit closes the fanotify group and is fail-open until systemd restart.
2. File descriptors opened before marks, and inherited pre-open descriptors,
   are outside fanotify's control.
3. Conservative topology watching has a small notification-to-mark race.
4. Migration access is not read-only on this backend.
5. `ssh-agent` signing authority is outside this file-access firewall after a
   user explicitly loads a key.
6. Privileged acceptance and real desktop/polkit behavior are not yet observed.
7. A runtime-only SSH enrollment does not dynamically add its parent to the
   topology watch set; re-protect it after replacement unless that parent is
   already watched by config.
8. The two harness source-of-truth files are outside this checkout under the
   supplied `/home/plfjy/Downloads/sensitive-data-firewall-harness/` directory;
   the adversarial harness pass reviewed both before implementation.

## Acceptance decision

Do not point this Alpha at real browser profiles or real SSH private keys yet.
Promote it to security-accepted Linux V1 only after all nine privileged suites
run successfully and their results are recorded without contradictory PASS /
BLOCKED claims.
