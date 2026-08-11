# Phase 23 — Interactive browser migration confirmation

## BASE HEAD

`5a156607acc5b5f86f6e907450256736e5fc0769` (`main` at task start).

## OLD BEHAVIOR

A trusted browser opening another enrolled browser profile without a manually
armed migration lease was immediately denied as `CrossBrowserWithoutLease`.

## NEW PRODUCT CONTRACT

Own-profile browser opens still allow immediately. Unknown processes, fake
browser executable names, arbitrary descendants and cross-UID access still
deny immediately. A trusted, enrolled same-UID browser opening another enrolled
browser profile returns typed `RequireMigrationConfirmation` and retains the
current permission operation pending.

## BROWSER RECOGNITION

The target BrowserId comes only from the existing canonical executable-path and
enrollment/trust identity lookup. No basename, argv, title, desktop entry, or
ancestor-name heuristic was introduced.

## PENDING FANOTIFY DESIGN

`PendingPermission` owns each event fd and fails closed in `Drop`; terminal
handling makes one response attempt and closes it. Requests deduplicate on UID,
stable target browser root, source browser and source profile. The store limits
requests to 8 and fds per request to 32. It expires after 60 seconds or target
process exit; limit and suppressed retries are denied and audited. The main
loop keeps polling/draining normal fanotify events while pending requests exist.

Observed Edge topology during a live import attempt: the trusted
`/opt/microsoft/msedge/msedge` executable launches
`--type=utility --utility-sub-type=chrome.mojom.ProfileImport` children beneath
the top-level Edge process. Pending requests use that top-most same-executable
ancestor as their target root, deduplicating importer children without trusting
arbitrary descendants with another executable.

## IPC

Protocol v3 adds typed `MigrationPendingList`, `MigrationPendingGet`, and
`MigrationResolve { id, action }`. Resolution accepts no client-supplied
browser, profile, PID, path, UID or duration. `AllowImport` uses a new
non-cached `org.guardd.migration-resolve` polkit action and revalidates the
live target identity before creating an immediately bound lease.

## GTK AND NOTIFICATIONS

guard-ui presents a dedicated libadwaita-styled browser-import dialog with
source/target browser, profile, target executable/PID and requested resource.
Close means Block. guard-ui's repeated application activations now only present
the existing primary window; they never construct another UI state or polling
loop. guard-notify emits and activates guard-ui on the single
`browser_migration_confirmation_required` audit event.

## LEASE BINDING, TIMEOUT, DEDUPLICATION, PID REVALIDATION

Allow creates the existing 10-minute `MigrationAccessLease` directly in
`Bound { root: ProcessStableId }` state for the triggering target process.
Before binding, PID/start time/path/dev/inode/UID/trust/BrowserId are checked
again. The lease remains source-browser/profile scoped and dies on root exit,
expiry or revocation. Rejection creates no lease and uses short
process-instance suppression.

## TEST RESULTS

Passed:

```text
cargo test -p guard-core -p guardd -p guard-ipc -p guard-client -p guard-ui -p guard-notify
37 guard-core + 81 guardd + IPC/client/UI/notifier tests: PASS
```

Coverage includes own profile allow, Edge→Chrome / Zen→Firefox /
Chromium→Chrome confirmation candidates, fake/untrusted identity and unknown
process denial, wrong UID denial, existing lease allow, and a pending approval
test proving the new lease binds to the verified browser root process instance.

## REAL BROWSER TESTS

BLOCKED, not passed. This host has Firefox only; Chromium/Chrome, Edge and Zen
were not installed. The process lacks `CAP_SYS_ADMIN` (`capsh` showed only
`cap_wake_alarm=i`), so it cannot create the required `FAN_CLASS_CONTENT`
group. The deterministic privileged command was attempted and stopped safely:

```text
$ bash scripts/test-browser-enforcement-root.sh
ERROR: this script must be run as root (needs CAP_SYS_ADMIN for fanotify).
```

No real browser profile or secret was opened. A human acceptance run
must use disposable profiles and the existing privileged browser harness, then
exercise each installed browser's built-in Import browser data workflow and
record any actual importer-helper topology before adding a narrow helper rule.

## KNOWN LIMITATIONS

Linux fanotify does not expose the original open flags, so a migration lease is
not a provable read-only grant. V1 deliberately does not treat arbitrary target
browser descendants as prompt-eligible.

## FINAL STATUS

Implementation and non-privileged test gate complete. Privileged fanotify and
real disposable-profile acceptance remain BLOCKED by this host's capabilities
and installed browser set.
