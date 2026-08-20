# Linux GUI protection/service lifecycle

Date: 2026-08-21

## Root cause

On Linux, the GUI had no first-run configuration candidate. The protection
switch therefore stopped with `active policy is unavailable` before invoking
the authenticated service helper. The switch also used `start`/`stop`, so it
did not persist the user's service choice. There is no safe, distro-independent
way for the GUI to install an Arch/Debian/RPM package; package installation
remains a release/AUR operation.

## Fix

- A missing Linux config now produces an empty draft. The GUI discovers
  browser/SSH candidates and keeps the protection switch disabled until the
  user selects at least one resource.
- Enabling from that reviewed draft writes and health-checks the config through
  the existing polkit `guardctl privileged apply-config` path, then enables and
  starts both `guardd.service` and the user `guard-notify.service`.
- An existing config can start the two services directly, even when the daemon
  was previously stopped.
- Service start/stop now use `systemctl enable --now` / `disable --now`, so the
  choice survives reboot. The fixed helper arguments remain closed; the GUI
  cannot provide an arbitrary unit or command.
- Missing service units are reported as an explicit “install the Linux release
  or AUR package first” error before a polkit prompt.

## Freeze impact

This is productization/UI lifecycle work. It does not change File Shield or
Process Shield authorization decisions, fanotify policy, BPF admission, audit
contents, or the frozen evidence. The only runtime change is persistence of
the already-authorized service lifecycle and first-run config hand-off.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `git diff --check`

All passed on the host as the normal development user. No real browser profile,
SSH key, cookie, token, or password store was read.
