# Linux desktop filesystem policy adjustment

Date: 2026-08-21

## Decision

The original project record intentionally kept two Linux backends: strict
filesystem-wide fanotify interception closes the replacement-inode first-open
race, while the scoped conservative backend is compatible with ordinary home
directories. A production desktop must not silently place a filesystem-wide
permission gate on `/` or on a shared `/home` mount.

The product defaults are therefore adjusted as follows:

- fresh GUI and `guardctl setup` configurations use `conservative`, which can
  protect a normal desktop profile without a root-filesystem mark;
- `strict-filesystem` remains an explicit, security-accepted option for a
  dedicated non-root filesystem and is no longer labelled as the normal desktop
  recommendation;
- the daemon's root-filesystem refusal and `GUARDD_ALLOW_ROOT_FS_MARK` safety
  boundary are unchanged;
- Conservative status remains `REDUCED` and is never presented as strict
  freeze-level `ACTIVE`.

This is not an authorization bypass or an attempt to make strict mode pretend
that a directory mark is filesystem-wide. It is a truthful deployment default
for the original “protect browser authentication data before open” product
scope. The stronger first-open replacement guarantee still requires the
explicit strict backend on an isolated filesystem.

## Failure handling

When a strict desktop configuration is explicitly selected on `/`, the GUI now
reports the reason before requesting polkit. If the main service start fails,
the notification service is stopped as part of rollback, so it cannot spin on a
missing guardd socket.

## Verification

Targeted GUI/CLI Clippy and tests pass. The existing freeze reports and evidence
were not edited. The developer's real browser data and SSH key contents were
not read; only service status and configuration metadata were inspected to
diagnose the startup failure.
