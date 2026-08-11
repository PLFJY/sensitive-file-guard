# Phase 09 — Desktop Notifications

> Historical report, superseded by Phase 16. Root `guardd` no longer runs
> `notify-send`; desktop presentation is handled by the unprivileged
> `guard-notify` user-session service.

## Implemented behavior

The notification presenter polls the authenticated daemon event API and reports
new blocked protected-data accesses in the logged-in user's desktop session.
Allowed browser self-access never notifies. Identical events for the same user,
process, executable, and resource are coalesced for ten seconds; the complete
events remain in the audit log.

Delivery is best-effort:

- The presenter invokes `notify-send` with the `guardd` application name.
- Missing notification tools or graphical sessions produce an error without
  affecting enforcement.
- Delivery is outside the authorization hot path.

The presenter also activates the GTK confirmation client for browser migration
and protected SSH-key confirmation events. The GTK client performs the
authenticated resolution through `guard-client`; policy remains in `guardd`.

## Hot-path impact

- Notification work runs only after the access decision and audit enqueue.
- Event coalescing is an in-memory hash-map lookup and insert.
- Notification failures cannot block fanotify authorization processing.

## Verification

The phase was verified with formatting, Clippy, and workspace tests without
root privileges or a graphical session. Synthetic IPC and metadata fixtures
were used; no real browser or SSH secrets were accessed.

Relevant coverage includes notification coalescing, no notification for allowed
self-access, migration-specific notification text, generic denial text, and
the no-graphical-session delivery path.

## Known limitations

Notification delivery depends on a working user-session D-Bus environment and
`notify-send`. A missing graphical session degrades presentation only; the
daemon's decision and audit behavior remain independent.

## Security notes

Notifications contain metadata such as executable basename, browser identity,
and resource kind only. They never include cookie values, passwords, key bytes,
database rows, or other protected contents.
