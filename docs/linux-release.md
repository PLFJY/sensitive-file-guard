# Linux release pipeline

The supported standalone Linux deliverable is a checksum-verified `tar.gz`
bundle produced from a clean source commit by
`packaging/linux/build-release.sh`. Compilation always runs as the normal user;
only the extracted bundle's `install.sh` needs root when targeting `/`.

## Build and contents

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
packaging/linux/build-release.sh
```

The artifact and its sidecar checksum are written under `dist/`. The bundle
contains its source commit, version, per-file SHA-256 manifest, and this fixed
runtime layout:

A formal build refuses a dirty source tree. A tag version must exactly match
`[workspace.package].version`; this prevents an artifact label from disagreeing
with the version embedded in the binaries. `--no-build` and an explicit version
exist only for the offline lifecycle test and pack already-built binaries.

| Payload | Destination | Mode |
|---|---|---|
| `guardd`, `guardctl`, `guard-ui`, `guard-notify` | `/usr/bin` | `0755` |
| daemon unit | `/usr/lib/systemd/system/guardd.service` | `0644` |
| notification unit | `/usr/lib/systemd/user/guard-notify.service` | `0644` |
| sysusers definition | `/usr/lib/sysusers.d` | `0644` |
| polkit policy | `/usr/share/polkit-1/actions` | `0644` |
| desktop entry, AppStream metadata, icon | `/usr/share` | `0644` |
| example config and documentation | `/usr/share/guardd`, `/usr/share/doc` | `0644` |

GTK4, libadwaita, systemd, polkit, libbpf, libelf, glibc, and their normal
runtime libraries remain distribution dependencies; they are not copied into
the bundle.

## Install and lifecycle contract

```sh
sha256sum -c sensitive-file-guard-linux-*.tar.gz.sha256
tar -xzf sensitive-file-guard-linux-*.tar.gz
cd sensitive-file-guard-linux-*
sudo ./install.sh install
```

Installation does not create `/etc/guardd/config.json` and does not enable the
daemon. The operator must review enrollment, then enable the service. Existing
configuration and audit state are preserved byte-for-byte across an ordinary
upgrade.

- Upgrade: verifies the bundle and validates the installed config with the
  candidate `guardctl` before replacing any destination file. An active daemon
  is restarted only after successful installation.
- Downgrade: refused by default. `install --allow-downgrade` still performs the
  candidate-schema validation first; an incompatible config leaves the current
  release untouched.
- Config migration: schema v1 needs no rewrite. A missing version is the
  documented v1 compatibility case. Future schemas must ship an explicit,
  separately tested migration; installers never silently discard unknown
  fields or lower the enforcement mode.
- Uninstall: removes release-owned files but preserves `/etc/guardd` and
  `/var/lib/guardd`. The system group is retained because deleting a group can
  reassign its numeric GID later.

`tests/check_linux_packaging.sh` exercises install, upgrade, downgrade refusal,
explicit compatible downgrade, incompatible-future-config refusal, permissions,
desktop/systemd layout, uninstall, and config/audit preservation in an offline
image root. The tag/workflow pipeline runs that test before uploading an
artifact. This packaging gate does not replace privileged File/Process Shield
acceptance and does not alter the frozen evidence.
