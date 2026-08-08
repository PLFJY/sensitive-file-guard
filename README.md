# Sensitive Data Firewall (Linux V1)

A narrow local capability firewall for sensitive files. It prevents
unauthorized local processes from reading protected local secrets **before**
the protected file is successfully opened.

> Core principle: **Prevent access, not exfiltration.**

## ⚠️ Do not test on real secrets

Never point this tool, its tests, or its fixtures at your real browser profiles,
cookies, saved passwords, session tokens, or real SSH private keys. All tests
use synthetic fixtures only (see `crates/guard-test-fixtures`). No test contains
network exfiltration code.

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
migration only under an explicit, temporary, read-only `MigrationLease`; an
explicit one-shot `SshLoadLease` for loading a private key into `ssh-agent`.

**Explicit V1 non-goals:** root/SYSTEM compromise; kernel exploits; browser
process injection; malicious browser extensions; browser remote-debugging
attacks; memory scraping of already-open secrets; an attacker engineered against
this project; full information-flow tracking after a user grants access; proving
every browser storage location is covered on every release.

## Architecture

```
                 CLI / TUI
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

Binaries: `guardd` (daemon), `guardctl` (control), `guard-tui` (terminal UI).

## Build

```sh
cargo build --release
```

Binaries are placed in `target/release/`: `guardd`, `guardctl`, `guard-tui`,
`guard-test-probe`.

## Install (systemd service)

```sh
# 1. Build release binaries.
cargo build --release

# 2. Install as a systemd service (run as root).
sudo deploy/install.sh

# 3. Edit the config — set your browser profile_root and ssh_keys.
sudo vi /etc/guardd/config.json

# 4. Start the service.
sudo systemctl start guardd

# 5. Verify enforcement is active.
guardctl status
# Expected: "guardd <version> — ACTIVE"

# 6. (Optional) enable auto-start on boot.
sudo systemctl enable guardd   # already done by install.sh
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

See [`deploy/guardd-config.example.json`](file:///home/plfjy/sensitive-file-guard/deploy/guardd-config.example.json)
for a template. Replace `REPLACE_USER` with your username and set the correct
`owner_uid`.

## Logs

```sh
journalctl -u guardd -f          # systemd
RUST_LOG=info                    # env var (set in the unit file)
```

## Status

Phases 01–14 complete. See `reports/` for per-phase reports. Phase 15 is the
final acceptance phase. See `sensitive-data-firewall-harness/` for the full
harness and [`docs/SECURITY_MODEL.md`](file:///home/plfjy/sensitive-file-guard/docs/SECURITY_MODEL.md)
for the security model.
