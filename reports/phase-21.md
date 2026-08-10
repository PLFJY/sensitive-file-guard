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
browsers, events, event detail, leases, lease revoke, and migration. The TUI
uses it through a compatibility re-export. `RequestOp::Events` now supports
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
passed; no graphical display was available for a real-window smoke run.

## Privileged regressions and limitations

`sudo -n true` returned `sudo: a password is required`. Strict fanotify,
browser adversarial, SSH broker, installed polkit/auth, and systemd privileged
regressions were therefore not run in this phase and remain **BLOCKED**, not
PASS. Existing Phase 19/19.1 Arch evidence remains the accepted baseline.
Snap/Flatpak remain unsupported; fanotify fail-open/crash and pre-open-fd
boundaries remain; package installation/publication still needs a human root
step.
