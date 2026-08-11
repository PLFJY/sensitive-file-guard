# Phase 21 — Linux control plane and GTK control center

Base/HEAD inspected: `867e77d270c341d57661c682cff45f1b0a7aaeb2`.

## Architecture

Added `crates/guard-client`, `apps/guard-ui`, shared Linux configuration and
native discovery in `platform-linux::config`, GTK packaging assets under
`data/`, and fixed-root control operations in `guardctl`. The GTK process is
an ordinary desktop-user client; it contains no policy evaluator and never
reads browser databases or SSH key contents.

## Control plane

`guard-client` owns the typed framed Unix-socket exchange for status, resources,
browsers, events, event detail, leases, lease revoke, and migration. `RequestOp::Events` now supports
bounded `before_id` and `after_id` cursors; both together are rejected, and
SQLite queries preserve ordinary-user UID filtering. Audit tests cover newest,
older, and newer pages.

`platform-linux::config` is the shared serde contract for enforcement mode,
browser enrollment, profile root, canonical executable paths, enrolled
executables, and SSH paths. The daemon consumes it directly and validates it
before engine startup. Existing security hot paths were not redesigned.

## Browser compatibility

Shared discovery recognizes native Firefox, Firefox ESR, Zen (Firefox-derived),
Chromium, Chrome, Brave, Edge, Opera (Chromium-derived), and Vivaldi only when
known executable paths exist and canonicalize. Zen and Opera layouts were
limited to maintained native Linux locations. Names, desktop files, package
metadata, argv[0], and process names are never trust inputs. Snap/Flatpak
profiles remain explicitly reported unsupported. `guardctl setup` remains
functional and accepts Zen suggestions.

## Privileged boundary

Hidden `guardctl privileged service start|stop|restart` and
`guardctl privileged apply-config` commands are intended for `pkexec`. They
accept no arbitrary unit, command, destination, or shell string. Config stdin
is capped at 256 KiB, parsed/validated through the shared contract, written to
fixed `/etc/guardd/config.json` with mode 0640 and root:guardd-users ownership,
fsynced and atomically renamed. Restart and active-state verification follow;
failed startup restores and restarts the previous bytes. Direct non-root
invocation fails first. `org.guardd.control` was added to the existing polkit
policy. Turning protection off is a service stop, not an enforcement mode.

## GTK UI

`guard-ui` uses GTK 4 and libadwaita 0.7-compatible APIs with an Adwaita
application window and standard widgets. It provides Overview with live
ACTIVE/DEGRADED/STOPPED/OFF/UNREACHABLE/NOT CONFIGURED states, daemon metrics,
and an authenticated master switch; Protection with Strict Filesystem
(recommended) versus Conservative, staged browser switches, individual
SSH-key paths, file chooser, Discard, and Apply & Restart; and a Security Log
with newest bounded audit events polled every two seconds. Only metadata is
shown.

First run uses shared discovery, stages Strict by default, and leaves SSH keys
empty. Blocking IPC, systemctl, and pkexec work runs via Gio's blocking pool;
GTK objects stay on the main context. A pure health-state test proves config
alone cannot show green.

## Post-review usability correction

Desktop review found the first GTK layout used an unconstrained paned sidebar,
placed an ordinary key button inside a list, used raw `GtkSwitch` suffixes that
could stretch into narrow vertical bars under the desktop theme, and allowed
timer ticks to queue another background refresh before a slow one completed.
The UI now has a fixed navigation width, header, scrollable content pages,
Adwaita boxed lists, native `AdwSwitchRow` controls, and normal-sized action
rows/buttons. IPC client reads and writes have a two-second bound, and refresh
has an in-flight guard, so a stalled local listener cannot accumulate work or
freeze the interface.

The Protection page now combines configured browser entries with native
discovery on every refresh and displays their configured/detected state.
It also adds a custom-browser dialog requiring a family, an existing absolute
profile root, and a canonical executable regular file. This is still a staged
candidate; applying it crosses the existing authenticated config boundary.

Refresh now rebuilds the browser source list from current discovery and the
staged configuration. Missing profile roots/executables are removed from the
staged browser enrollments and disappear from the list; the change remains
staged until Apply. Configured browsers and SSH keys each have an explicit
remove-protection button. SSH startup now also shows safe metadata-only
suggestions for conventional `~/.ssh/id_*` files as `Detected — not protected`
until explicitly selected. The UI source model now distinguishes
`NativeDetected` from `Custom`: native entries have no trash action, while
custom browser paths and manually selected SSH keys do. Trash actions use a
fixed centered square size so desktop themes cannot stretch them into narrow
vertical controls.

The Overview protection switch is now a bundle control for both the observed
`guardd.service` and the logged-in user's `guard-notify.service` states, not an
initial local default. It polls every two seconds, reflects changes made
through `systemctl` or `guardctl`, and suppresses the switch callback during
synchronization so a refresh cannot trigger a second privileged action. The
bundle is on only when both units are active; a missing notification unit makes
the health state `DEGRADED` and leaves the switch off. Start/stop uses
best-effort rollback so a failed half does not intentionally leave the other
half running alone.

Release builds persist, print, and trace denied decisions only. The daemon IPC
also hides historical allow rows from `events`/`explain`, and the GTK log
filters to blocked events, so normal allows do not consume audit storage or
fill production logs. Debug builds retain the full decision stream for
diagnostics and tests.

## Packaging and docs

Source installation now installs `guard-ui`, a desktop entry, AppStream
metadata, and an original SVG icon. AUR `PKGBUILD`/`.SRCINFO` include the UI,
GTK/libadwaita dependencies, and assets without auto-starting anything.
README, installation, and security-model docs describe the client boundary and
GTK dependencies.

`makepkg --printsrcinfo` and `namcap PKGBUILD` passed. A clean VCS makepkg run
also completed against the remote source snapshot; because this worktree's
phase changes are not committed to that snapshot, its archive predates the UI
and was not treated as final package-content evidence. Rebuild from a commit
carrying Phase 21 before publishing.

## Validation

The following all passed: `cargo fmt --check`; clippy with `-D warnings`;
workspace all-feature tests; release workspace build excluding the probe;
`git diff --check`; shell syntax; and `systemd-analyze verify` on the rendered
unit. Focused helper tests reject malformed, oversized, empty, relative-path,
and unsupported-mode candidates. Direct non-root helper smoke tests returned
the expected root-required error. GTK compilation and the health-state test
passed; a Wayland startup smoke (`timeout 3s env GDK_BACKEND=wayland
target/release/guard-ui`) kept the process alive until the expected timeout.
The release `guardd` test suite also passed with allow-event audit suppression
enabled.

## Privileged regressions and limitations

`sudo -n true` returned `sudo: a password is required`. Strict fanotify,
browser adversarial, SSH broker, installed polkit/auth, and systemd privileged
regressions were therefore not run in this phase and remain **BLOCKED**, not
PASS. Existing Phase 19/19.1 Arch evidence remains the accepted baseline.
Snap/Flatpak remain unsupported; fanotify fail-open/crash and pre-open-fd
boundaries remain; package installation/publication still needs a human root
step.
