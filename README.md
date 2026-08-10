# Sensitive Data Firewall (Linux V1)

> **Current status: SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST when configured
> with `strict-filesystem`.** Conservative mode remains available and retains
> its measured replacement-inode race; it is not the security-accepted backend.
> This is an Alpha with the explicit non-goals below, not a claim of protection
> against root, browser compromise, or already-open descriptors.

A narrow local capability firewall for sensitive files. It prevents
unauthorized local processes from reading protected local secrets **before**
the protected file is successfully opened.

> Core principle: **Prevent access, not exfiltration.**

## ⚠️ Do not test on real secrets

Never point this tool, its tests, or its fixtures at your real browser profiles,
cookies, saved passwords, session tokens, or real SSH private keys. All tests
use synthetic fixtures only (see `crates/guard-test-fixtures`). Tests never use
IP networking; the adversarial harness can send only a generated canary to an
AF_UNIX socket below its disposable test directory.

## What it protects (V1)

1. Browser authentication/session data: cookies + sidecars, session data,
   browser key material, selected Local/Session Storage and IndexedDB trees,
   saved-login databases (secondary priority).
2. SSH private keys: raw private-key bytes are normally unreadable to ordinary
   applications; normal SSH/Git workflows should use `ssh-agent`.

## Threat model

**Blocks:** ordinary same-user cookie stealers directly opening/copying protected
browser files; Python/Node/shell scripts reading protected browser data;
malicious build/postinstall scripts reading protected data; ordinary processes
reading/copying registered SSH private keys; coding/AI agents reading SSH
private-key files.

**Allows:** a browser accessing its own profile; normal `git push`, SSH
authentication, and SSH-format Git signing through `ssh-agent`; cross-browser
migration only under an explicit, temporary `MigrationAccessLease` that binds
on first use to one exact process tree; an
explicit one-shot `SshLoadLease` for loading a private key into `ssh-agent`.
The Linux fanotify backend does **not** claim that migration access is
read-only because permission events do not reveal the opener's original flags.

**Explicit V1 non-goals:** root/SYSTEM compromise; kernel exploits; browser
process injection; malicious browser extensions; browser remote-debugging
attacks; memory scraping of already-open secrets; an attacker engineered against
this project; full information-flow tracking after a user grants access; proving
every browser storage location is covered on every release. The open-only
fanotify backend also does not observe an inode that is renamed into and back
out of a sensitive pathname without any open occurring while it has that name.

## Architecture

```
              CLI / TUI / guard-notify
                     |
              local authenticated IPC
                     |
                +----v-----+
                |  guardd  |   privileged root daemon (owns fanotify perm group)
                |----------|
                | policy   |
                | identity |
                | resources|
                | leases   |
                | audit    |
                +----+-----+
                     |
          fanotify FAN_OPEN_PERM (CAP_SYS_ADMIN)
                     |
          protected filesystem resources
```

Binaries: `guardd` (daemon), `guardctl` (control), `guard-ui` (native GTK/libadwaita
control center), `guard-tui` (terminal UI), and `guard-notify` (unprivileged
user-session notification presenter).

## Graphical control center

`guard-ui` is the preferred interactive Linux client. It shows live ACTIVE,
DEGRADED, STOPPED, UNREACHABLE, and NOT CONFIGURED states; stages Strict or
Conservative policy and individual browser/SSH-key enrollments; applies a
complete candidate through the authenticated `guardctl` helper; and displays
the daemon's audit log. It never writes `/etc/guardd/config.json`, evaluates
policy, or runs as root. `guardctl` remains the supported CLI/automation tool.

## Install

The main guide is [Linux installation and deployment](docs/INSTALL_LINUX.md).
It covers the supported systemd baseline, Arch/Debian/Ubuntu/Fedora dependency
commands, native browser discovery, configuration, service operation, updates,
and removal.

**Security-accepted Alpha: `strict-filesystem` on the tested Arch host.**
Other mainstream systemd-based distributions are expected to work with native
browser packages but have not received equivalent privileged acceptance
testing. Snap and Flatpak browsers are currently unsupported for the
security-accepted path.

### Short source quick-start

```sh
# As your normal user, from a source checkout:
cargo build --release
sudo deploy/install.sh
sudo guardctl setup --home "$HOME"
sudo systemctl enable --now guardd
systemctl --user enable --now guard-notify
guardctl status
```

The installer installs already-built binaries; it does not build as root,
enable, or start the daemon. `guardctl setup` writes a new, reviewed strict
configuration only after finding native browser profile/executable pairs.

## Run (without systemd)

```sh
# Start the daemon (requires CAP_SYS_ADMIN for fanotify enforcement).
sudo target/release/guardd \
    --enforce-browser-config /path/to/config.json \
    --ipc-socket /run/guardd/guardd.sock \
    --audit-db /var/lib/guardd/audit.db

# In another terminal: query status.
target/release/guardctl --socket /run/guardd/guardd.sock status

# Terminal UI:
target/release/guard-tui /run/guardd/guardd.sock
```

## Config

See [`deploy/guardd-config.example.json`](deploy/guardd-config.example.json)
for a deliberately empty strict-mode template. It contains no username, UID,
profile, or guessed SSH-key path. Use `sudo guardctl setup --home "$HOME"` to
generate a new reviewable native-browser configuration without `owner_uid`;
guardd stats the
existing profile root; it fails rather than silently substituting UID 0.

Linux enforcement is explicit:

```json
{
  "enforcement_mode": "strict-filesystem"
}
```

- `conservative` is a compatibility mode that marks discovered objects and
  directories, then uses inotify rediscovery. It has lower overhead but a
  measured first-open race for replacement inodes.
- `strict-filesystem` installs `FAN_MARK_FILESYSTEM | FAN_OPEN_PERM` once per
  distinct protected filesystem. It classifies new sensitive paths before the
  first open completes. A structural path hit immediately records the inode
  before guardd answers the permission event, so a later rename outside the
  namespace remains inode-protected. It is opt-in because it intercepts all
  opens on those filesystems and has a measurable cost.

`guardctl status` reports `mode`, observed/required filesystem-mark counts and
kernel mark health, strict-event and fast-allow counters,
protected/allowed/denied counts, queue overflows, audit
drops, classifier failures, topology health, and hardlink-alias scans. Strict
startup fails instead of reporting ACTIVE if any required profile/key
filesystem cannot be marked.

## Logs

```sh
journalctl -u guardd -f          # systemd
RUST_LOG=info                    # env var (set in the unit file)
```

## Defensive browser adversarial acceptance

Run this from the intended Arch desktop user's logged-in session. It builds
unique disposable Firefox/Chromium profiles below `/tmp`, exercises ordinary
read, mmap, SQLite, copy, links, rename, child, `/proc/PID/fd`, replacement
inode, nested-resource, and local-sink paths, then deletes the fixtures:

```sh
sudo bash scripts/test-browser-adversarial-root.sh
```

An enforcement PASS requires all three facts: the probe returned failure, its
output contained no canary, and a new audit `Deny` appeared. Notification
delivery is a separate assertion and never substitutes for access denial. When
a working `org.freedesktop.Notifications` desktop service is available, every
audited adversarial DENY is offered as a visible “Blocked protected-data
access” notification and the delivered/expected totals must match. Use
`KEEP_WORK=1` only when you intentionally want to retain the synthetic audit
artifacts for inspection.

The observed Arch result was `PASS=24 FAIL=0 BLOCKED=0`, including 15/15 mako
deliveries. This is strong steady-state evidence, but it does not make the
inotify rediscovery interval race-free.

## Defensive SSH broker acceptance

The SSH suite creates its own temporary HOME, ephemeral key, disposable system
OpenSSH agent, same-UID fake listeners, and hostile loader environment. It
never touches `~/.ssh` or an existing `SSH_AUTH_SOCK`:

```sh
sudo bash scripts/test-ssh-broker-adversarial-root.sh
```

The broker verifies both the stopped system `ssh-add` child and the connected
agent's kernel credentials/stable executable identity. It pins the verified
agent socket inode behind a root-controlled pathname, sanitizes the exec
environment, binds the live `ssh-add` environment to that exact pin on the
permission-event hot path, and grants one protected-key open for 30 seconds.
The observed result was `PASS=29 FAIL=0 BLOCKED=0`; even a non-cooperative
client that ignored the returned pin could not load the key, and the malicious
listeners received zero private-key bytes.

## Topology race measurement

This synthetic-only stress harness compares the conservative watcher interval
with strict first-open enforcement:

```sh
sudo bash scripts/test-topology-race-stress-root.sh
sudo ENFORCEMENT_MODE=strict-filesystem \
  bash scripts/test-topology-race-stress-root.sh
```

On the tested `/tmp` tmpfs, the Phase 18 conservative measurement allowed all
10,000 immediate replacement reads (1171/2225/2347/4039 microseconds
p50/p95/p99/max to convergence). The Phase 19 conservative rerun again allowed
10,000/10,000. Strict Mode denied 10,000/10,000 immediate reads with zero
recoveries. A separate 10,000-iteration external-hardlink/replacement attack
also had zero recoveries after the strict alias check was added.

The Phase 19.1 rename-away regression additionally proved both an owning
browser's first open and a denied first open promote the new inode before it is
renamed outside the profile. Both cases had zero recoveries. A rename-only
transit with no open at the sensitive name remains outside `FAN_OPEN_PERM` and
is documented rather than presented as protected. A targeted 16,000-open
multi-hardlink amplification run completed in 889 ms with no queue overflow,
classifier failure, or audit drop.

Run the broader strict and performance acceptance with:

```sh
sudo bash scripts/test-strict-filesystem-root.sh
sudo bash scripts/test-strict-concurrency-root.sh
sudo bash scripts/benchmark-strict-filesystem-root.sh
```

On this host, a 100,000-open unprotected workload on the marked ext4
filesystem fell from about 900k opens/s without guardd to about 72.6k opens/s
in Strict Mode (12.41x wall-time). The bounded 180,624-event concurrent run had
zero fanotify overflows, audit drops, classifier failures, or deadlocks. See
[`reports/phase-19.md`](reports/phase-19.md). The post-review rename-away fix
and evidence are in [`reports/phase-19.1.md`](reports/phase-19.1.md).

## Status

Hardening Pass 2 and Strict Filesystem Enforcement are implemented. Every
mandatory privileged suite was actually run on the target Arch host;
strict first-open/replacement/alias tests, steady-state browser protection, the
hardened SSH broker, real systemd recovery/polkit, audit-content scans, desktop
notifications, queue stress, and Rust quality gates passed. Linux V1 is
**SECURITY-ACCEPTED ALPHA ON TESTED ARCH HOST in `strict-filesystem` mode**.
Conservative mode is explicitly not promoted. See
[`reports/phase-16.md`](reports/phase-16.md),
[`reports/phase-17.md`](reports/phase-17.md), and
[`reports/phase-18.md`](reports/phase-18.md),
[`reports/phase-19.md`](reports/phase-19.md),
[`reports/phase-19.1.md`](reports/phase-19.1.md), plus
[`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).
