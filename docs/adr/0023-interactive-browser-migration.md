# ADR 0023: Interactive browser migration confirmation

## Context

The earlier model required a manually armed `MigrationAccessLease` before a
trusted browser could import another browser's profile. That made ordinary
browser import UX fail closed even when a human was present.

## Decision

The pure policy returns a typed `RequireMigrationConfirmation` only for a
same-UID, positively enrolled/trusted target browser opening a different
enrolled browser profile without a lease. The fanotify loop moves that event
fd into a bounded RAII pending store and continues processing all other
events. One request deduplicates matching resource opens for the source
profile and exact target process instance.

guard-ui resolves only a daemon-issued pending ID and fixed allow/block enum.
Allow requires a non-cached `org.guardd.migration-resolve` polkit action. The
daemon revalidates target PID/start time/executable identity/UID/BrowserId and
creates a lease immediately bound to the top-most same-executable browser root
of that exact tree, with the existing
10-minute duration. Block, close, timeout, target exit and revalidation failure
deny all queued fds. A short process-scoped negative cache suppresses retries.

Manual `guardctl migration authorize` remains for advanced or headless
pre-authorization and still creates its existing armed lease.

## Consequences

Unknown processes, fake browser names, arbitrary browser descendants and
cross-user access remain immediate denials and never receive a dialog. The
notification cannot approve an import. Pending fd ownership guarantees one
allow/deny response and close; limits prevent fd accumulation. Fanotify cannot
prove a lease is read-only because it does not provide the triggering open
flags. Real browser importer helper topology is not generalized without
observed evidence; V1 recognizes the actual trusted opener only.
