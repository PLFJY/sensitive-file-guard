# Sensitive Data Firewall (Linux V1)

> **Current status: implementation-complete Alpha; security acceptance is
> pending privileged integration tests. Do not use real browser data or SSH
> private keys yet.**

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
every browser storage location is covered on every release.

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

Binaries: `guardd` (daemon), `guardctl` (control), `guard-tui` (terminal UI),
and `guard-notify` (unprivileged user-session notification presenter).

## Build

```sh
cargo build --release
```

Binaries are placed in `target/release/`: `guardd`, `guardctl`, `guard-tui`,
`guard-notify`, `guard-test-probe`.

## Install (systemd service)

```sh
# 1. Build release binaries.
cargo build --release

# 2. Install as a systemd service (run as root).
sudo deploy/install.sh

# The installer adds the invoking sudo user to guardd-users. Log out/in once
# so the new group is present in the user session.

# 3. Edit the config — set your browser profile_root and ssh_keys.
sudo vi /etc/guardd/config.json

# 4. Start the service.
sudo systemctl start guardd

# 5. Verify enforcement is active.
guardctl status
# Expected: "guardd <version> — ACTIVE"

# 6. (Optional) enable auto-start on boot.
sudo systemctl enable guardd   # already done by install.sh

# 7. Desktop notifications run in the user session, never in root guardd.
systemctl --user daemon-reload
systemctl --user enable --now guard-notify
```

### Uninstall

```sh
sudo deploy/install.sh --uninstall
# Config (/etc/guardd/) and audit DB (/var/lib/guardd/) are preserved.
```

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
for a template. Replace `REPLACE_USER` with your username and set the correct
`owner_uid`.

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

## Status

Hardening Pass 1 is implemented and its non-privileged gates pass. The nine
root/CAP_SYS_ADMIN acceptance scripts have not been run in this environment;
Linux V1 therefore remains **security-acceptance pending**. See
[`reports/phase-16.md`](reports/phase-16.md),
[`reports/phase-17.md`](reports/phase-17.md), and
[`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).
