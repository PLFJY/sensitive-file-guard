# Linux installation and deployment

This deployment supports mainstream systemd-based Linux distributions with
fanotify permission events and `/proc`. `guardd` is a root service because
`FAN_CLASS_CONTENT` / `FAN_OPEN_PERM` require `CAP_SYS_ADMIN`; it needs polkit
`pkcheck`. `guard-notify` needs a working user D-Bus session and `notify-send`.
Start its user unit only after the `guardd-users` supplementary group has
refreshed; diagnose delivery with `journalctl --user -u guard-notify`.

| Status | Install form |
| --- | --- |
| Tested / security-accepted Alpha | Native packages on the Phase 19/19.1 Arch host, `strict-filesystem` only. |
| Expected to work | Explicit native Firefox, Firefox ESR, Chromium, or Chrome config on Arch, Debian, Ubuntu, Fedora; privileged acceptance did not run there. |
| Experimental | Explicit custom Brave, Edge, Vivaldi, or maintained custom executable paths. |
| Unsupported | Snap/Flatpak browsers on the security-accepted path; non-systemd deployments. |

Never use a real Cookies database, browser secret, or SSH private key for a test.

## Dependencies

| Distribution | Build dependencies | Runtime dependencies |
| --- | --- | --- |
| Arch | `sudo pacman -S --needed base-devel cargo rust git clang gtk4 libadwaita` | `sudo pacman -S --needed libbpf systemd polkit`; optional `libnotify openssh` |
| Debian | `sudo apt install build-essential cargo rustc git clang pkg-config libbpf-dev libgtk-4-dev libadwaita-1-dev` | `sudo apt install libbpf1 systemd polkitd`; optional `libnotify-bin openssh-client` |
| Ubuntu | `sudo apt install build-essential cargo rustc git clang pkg-config libbpf-dev libgtk-4-dev libadwaita-1-dev` | `sudo apt install libbpf1 systemd polkitd`; optional `libnotify-bin openssh-client` |
| Fedora | `sudo dnf install gcc make cargo rust git clang libbpf-devel gtk4-devel libadwaita-devel` | `sudo dnf install libbpf systemd polkit`; optional `libnotify openssh-clients` |

Current official metadata confirms Debian `polkitd` provides `pkcheck`; Arch
and Fedora use `polkit`; Arch `libnotify` provides `notify-send`.

### SSH behavioral backend compatibility

The Phase 22.1 model requires an attached BPF LSM `socket_sendmsg` hook to block
an actual outbound send from the reader's process tree, including a socket
opened before the key was read. It needs an active `bpf` entry in
`/sys/kernel/security/lsm`, kernel BTF at `/sys/kernel/btf/vmlinux`, and the
privilege/runtime loader required to attach the program. The package needs
libbpf at runtime and clang while building the embedded object. It leaves raw
SSH reads fail-closed whenever loading or attachment fails. Check `guardctl
status` for `ssh_behavior_backend`; `UNAVAILABLE` or `DEGRADED` is not
behavioral SSH protection.

The GTK overview intentionally shows a short actionable message when this
backend is unavailable; full libbpf/verifier diagnostics remain in
`journalctl -u guardd` rather than being rendered into the user interface.

The `guardd` system unit bounds `CAP_BPF` and `CAP_PERFMON` in addition to the
existing fanotify/process capabilities. These are the minimum capabilities
used by libbpf for the BPF-LSM and scheduler tracepoint links; the unit does
not use a broad privileged capability set. `guardctl status` includes a build
identifier (`version` such as `0.1.0+<commit>`) so an acceptance run can verify
that the running daemon is the installed build.

`guard-ui` is an unprivileged GTK 4/libadwaita presentation and control client;
it is not auto-started and never replaces `guardctl` for automation.
Launch it from the logged-in desktop session with `guard-ui` (or the
“Sensitive File Guard” application entry after installation). For a source
checkout before installation, use `target/release/guard-ui`.

## Source installation

```sh
git clone https://github.com/PLFJY/sensitive-file-guard.git
cd sensitive-file-guard
cargo build --release                 # normal user
sudo deploy/install.sh                # installs existing artifacts only
```

Source installation uses `/usr/local/bin`, `/etc/systemd/system`,
`/usr/local/lib/systemd/user`, and `/usr/local/share/polkit-1/actions`. It does
not build as root, create or overwrite `/etc/guardd/config.json`, enable, or
start guardd.
It creates `guardd-users` and adds the sudo-invoking user. To choose another
account explicitly: `sudo usermod -aG guardd-users alice`. Log out/in before
using `guardctl` or `guard-notify` so supplementary groups refresh.

## Configuration and browser portability

There is intentionally no active default `/etc/guardd/config.json`: an empty
strict-mode configuration would look protected while protecting no resources.
The packaged template is only an example. It has no username, UID 1000,
guessed profile, or guessed SSH key.

For a supported native browser installation, create a configuration with the
explicit setup command:

```sh
# "$HOME" expands before sudo, so the selected desktop user's home is explicit.
sudo guardctl setup --home "$HOME"
```

The command prints the proposed JSON, requires `yes` before writing, creates
only a new `/etc/guardd/config.json` with mode `0600`, and does not start the
daemon. It refuses to overwrite an existing file, refuses to emit an empty
configuration, and omits unsupported Snap/Flatpak roots and all SSH keys. Use
`--yes` only for an already-reviewed non-interactive invocation. If the command
runs as root, `--home` is mandatory so `/root` is never selected accidentally.

For custom browser layouts, inspect suggestions and build the explicit config
yourself:

```sh
guardctl browser discover
guardctl browser discover --home /home/alice  # deliberate other-user setup
guardctl ssh suggest                          # list, never read, candidates
```

Discovery emits only existing profile roots and canonical existing native
executables. It never changes config, queries package metadata, or grants
trust. Review output and copy wanted entries; omit `owner_uid` so guardd stats
the root and fails rather than silently substituting a UID. Add SSH keys only
after deliberately selecting an existing suggestion; strict requires each
configured key to exist.

```json
{"enforcement_mode":"strict-filesystem","browsers":[{"id":"firefox","family":"Firefox","profile_root":"/home/alice/.mozilla/firefox","exe_paths":["/usr/lib/firefox/firefox"]}],"enrolled_exes":[],"ssh_keys":[],"ssh_behavior_window_secs":10}
```

| Native form | Profile root | Final executable candidates |
| --- | --- | --- |
| Arch / Debian / Ubuntu Firefox | `~/.mozilla/firefox` | `/usr/lib/firefox/firefox` |
| Fedora Firefox | `~/.mozilla/firefox` | `/usr/lib64/firefox/firefox` |
| Debian Firefox ESR | `~/.mozilla/firefox-esr` | `/usr/lib/firefox-esr/firefox-esr` |
| Arch / Debian Chromium | `~/.config/chromium` | `/usr/lib/chromium/chromium` or `/usr/lib/chromium-browser/chromium-browser` |
| Fedora Chromium | `~/.config/chromium` | `/usr/lib64/chromium-browser/chromium-browser` |
| Google Chrome | `~/.config/google-chrome` | `/opt/google/chrome/chrome` |

Brave, Edge, Vivaldi, and custom builds remain supported by explicit reviewed
`exe_paths`; the helper knows common native locations. Do not use `command -v
firefox`: `/usr/bin/firefox` can be a wrapper. Configure the canonical regular
executable observed at `/proc/<browser-pid>/exe`, never a process/package name.

Snap Firefox and Flatpak Firefox/Chromium are explicitly unsupported. This
Alpha has not established stable host `/proc/<pid>/exe` identity or filesystem
mark visibility across their mount namespaces. Matching sandbox IDs or names
would weaken identity checks; use native packages for the accepted path.

## Arch AUR package

`packaging/aur/` contains the VCS package `sensitive-file-guard-git`; no stable
upstream tag exists yet. Build it with `makepkg -si` from that directory after
reviewing the PKGBUILD. It installs binaries in `/usr/bin`, units in
`/usr/lib/systemd/{system,user}`, policy in `/usr/share/polkit-1/actions`, the
empty template in `/usr/share/guardd`, and a `sysusers.d` definition for
`guardd-users`. It deliberately does not install `/etc/guardd/config.json` or
enable/start guardd. After package installation:

```sh
sudo usermod -aG guardd-users "$USER"
# log out/in; discover and confirm a native browser configuration
sudo guardctl setup --home "$HOME"
sudo systemctl enable --now guardd
systemctl --user enable --now guard-notify
```

## Start, verify, update, uninstall

```sh
sudo systemctl enable --now guardd
systemctl --user daemon-reload
systemctl --user enable --now guard-notify
guardctl status
guardctl resources list
guardctl browsers list
guardctl events
journalctl -u guardd --no-pager
systemctl status guardd
systemctl --user status guard-notify
```

Healthy Strict status is `mode = strict-filesystem`, `ACTIVE`, healthy required
filesystem marks, and zero classifier failures, queue overflows, and audit drops
under normal startup. Missing roots/keys or failed marks must not become ACTIVE.
When no configuration exists, the provided unit is deliberately skipped by its
`ConditionPathExists` rather than restart-looping; run `guardctl setup` first.
`conservative` is compatibility-only and has the known replacement/topology race.

To update: stop guardd, update source, build unprivileged, run the installer,
then start after review. Uninstall with `sudo deploy/install.sh --uninstall`;
it preserves `/etc/guardd` and `/var/lib/guardd` for manual inspection/removal.

Troubleshoot with `journalctl -u guardd -b`; verify configured paths instead of
switching modes to hide a mark failure. Install `polkit` (Arch/Fedora) or
`polkitd` (Debian/Ubuntu) if `pkcheck` is missing. Non-systemd users must build
an equivalent hardened root service manually; that form is untested.
