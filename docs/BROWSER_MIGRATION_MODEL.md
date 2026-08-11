# Browser migration model

Browser profile protection is a pre-open firewall. The outcome depends on the
daemon-verified executable identity of the opener, not its basename, command
line, window title, or desktop entry.

| Opener | Protected profile | Result |
| --- | --- | --- |
| Enrolled Chrome | Chrome | Allow immediately |
| Enrolled Edge | Chrome | Hold current open and ask |
| Enrolled Zen | Firefox | Hold current open and ask |
| Enrolled Chromium | Chrome | Hold current open and ask |
| Unknown process / npm / node | Chrome | Deny immediately |
| Fake `/tmp/chrome` | Chrome | Deny immediately |
| Any other UID | Chrome | Deny immediately |

## Own browser

An enrolled, trusted browser reading its own enrolled profile is allowed with
no popup. This includes protected cookies, login databases, local state,
sessions, Local Storage, IndexedDB, and Firefox profile resources.

## Unknown process

A non-browser process is denied before its open succeeds. A pathname or
basename that contains `chrome` is not browser identity. Browser descendants
are not automatically trusted either: `Chrome -> bash -> cat Cookies` is
denied unless an already-bound migration lease covers that exact tree.

## Trusted other browser

When an enrolled trusted Browser B accesses Browser A's profile for the same
UID without a valid lease, guardd keeps the triggering `FAN_OPEN_PERM` pending.
It emits one confirmation event and guard-notify activates guard-ui. Matching
opens from the same Browser B process instance into the same source profile
join that one bounded pending request; unrelated fanotify traffic keeps moving.

The dialog identifies source browser/profile, target browser/executable/PID,
and the first requested resource. Selecting **Yes, allow this import** requires
interactive polkit authorization. Selecting **No, block**, closing the dialog,
target process exit, or the 60-second timeout denies every queued operation.

## Approved import

After approval guardd revalidates the PID, start time, canonical executable
path, executable device/inode, UID, trust tier, and BrowserId mapping. It then
creates a 10-minute `MigrationAccessLease` already bound to the exact target
browser process tree. Subsequent matching reads for that source browser and
profile use `AllowByLease`; another profile needs another confirmation. The
lease dies when its root browser exits, expires, or is revoked.

Linux fanotify does not expose the original open flags, so this is not a
provable read-only grant. The UI correctly says “allow this import.”

## Rejected import

No lease is created. The daemon records `browser_migration_blocked` and keeps
a short process-instance-scoped rejection suppression window so repeated opens
do not produce a popup storm. A newly launched browser can ask again.

Examples: Edge importing Chrome, Chrome importing Firefox, Zen importing
Firefox, and Chromium importing Chrome may ask. A fake Chrome executable, npm
reading Cookies, and cross-user access never ask and remain fail-closed.
