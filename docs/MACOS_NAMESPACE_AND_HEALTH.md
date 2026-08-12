# macOS namespace mediation and enforcement health

The macOS extension subscribes to `AUTH_OPEN`, `AUTH_LINK`, and `AUTH_RENAME`.
All authorization responses use Endpoint Security with caching disabled.
`AUTH_LINK` and `AUTH_RENAME` are deterministic: the callback never waits for
the UI or treats a migration/SSH read lease as namespace-mutation authority.

Protected exact files are anchored by device/inode identity. Browser tree
descendants are discovered into a bounded identity index outside the callback,
so a pre-existing hardlink outside a profile remains protected. Kernel-observed
target identity also protects reads through symlinks. The index is refreshed
after relevant namespace activity or an ES sequence gap; scanning happens on a
new snapshot and only the final replacement takes the writer lock.

Unknown clients cannot link or rename a protected object, rename a protected
parent directory, or replace a protected path. A verified enrolled browser may
perform its normal atomic updates only when source and destination remain in
the same enrolled browser/profile namespace. Exact Team ID, signing ID, bundle
path, executable identity, and owner UID checks still apply. SSH private keys
never receive a namespace-mutation exception.

## Health contract

Authenticated status responses expose stable `backend_state` categories:

- `ACTIVE`: Endpoint Security is enforcing normally.
- `DEGRADED`: enforcement remains active, but sequence loss, process ancestry
  uncertainty, a bounded-index limit, a response failure, or another repairable
  runtime fault was observed.
- `NOT_ENFORCING`: the service is reachable without active policy mediation.
- `REQUIRES_APPROVAL`: entitlement/system-extension approval or privilege is
  missing.
- `REQUIRES_FULL_DISK_ACCESS`: Endpoint Security client creation was rejected
  for TCC Full Disk Access.

The host lifecycle UI separately reports an extension that is not installed.
It never modifies TCC, System Integrity Protection, Secure Boot, or another
global security setting.

The optional `mac_health` object contains ES per-type/global sequence-gap
totals, pending-created/resolved/timed-out/deadline/late-response totals,
namespace allow/deny totals, alias-index size/capacity/saturation, and process-
graph degradation. A process-event sequence gap disables ancestry-derived
leases until restart; a directly verified browser can still be recognized,
but missing ancestry never falls back to UID or process name.

Restart reloads configuration and creates fresh resource/process snapshots.
Pending opaque ES operations and all approval leases are memory-only and are
not restored. A crash necessarily creates a gap until macOS restarts the
extension; the product reports availability after restart and does not claim
continuous mediation during that unavoidable interval.

## Disposable acceptance

On a SIP-off self-use or formally provisioned host with the extension activated
and Full Disk Access:

```sh
scripts/macos/run-namespace-health-acceptance.sh
```

The script uses only a `mktemp` Chrome profile. It checks a pre-existing
hardlink alias, a symlink read, link-out, rename-out, protected-parent rename,
health metrics, and a real browser restart for atomic-update compatibility.
It exits 77 before creating fixtures when the activated authenticated extension
is unavailable.
