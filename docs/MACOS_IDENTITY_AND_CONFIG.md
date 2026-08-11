# macOS process identity, browser trust, and configuration

Phase 04 maps Endpoint Security facts to the existing portable process model.
The authorization path never uses a process basename. Its stable identity is
PID plus audit-token PID version, ES process start time, canonical executable
path, and executable `st_dev`/`st_ino`, with UID/GID checked separately.

## Process graph

The Endpoint Security client subscribes to AUTH_OPEN and only the three
notifications needed for ancestry: fork, exec, and exit. Graph keys are audit
PID/PID-version pairs, values retain the full stable executable identity, and
parent edges come from the parent audit token. Entries expire after ten minutes
and the graph is capped at 4096 entries. An absent, stale, cyclic, or over-depth
parent chain fails closed; same UID is never treated as proof of ancestry.

## Browser trust

Automatic discovery is limited to these verified defaults:

| Browser | Profile root | Main signing identity |
|---|---|---|
| Google Chrome | `~/Library/Application Support/Google/Chrome` | `EQHXZ8M8AV/com.google.Chrome` |
| Chromium | `~/Library/Application Support/Chromium` | `EQHXZ8M8AV/org.chromium.Chromium`; otherwise custom enrollment is required |
| Firefox | `~/Library/Application Support/Firefox/Profiles` | `43AQ936H96/org.mozilla.firefox` |

Known content/GPU helper executables are individually enrolled by canonical
path inside the matching `.app` plus exact Team ID and signing ID. A matching
Team ID on an arbitrary executable grants nothing. Strict static-code
validation is performed with Security.framework; cdhash is shown for update
diagnostics but is not permanently pinned for signed vendor updates.

An explicit unsigned or user-writable custom executable is enrolled by its
canonical path, file identity, size, mtime/ctime, and SHA-256. Configuration
load rehashes it outside the ES callback. Changed bytes or metadata invalidate
trust until explicit reenrollment.

The metadata-only diagnostic command is:

```sh
target/debug/guard-ui --discover-macos-browsers
```

It checks app signatures and whether known profile roots exist. It does not
open, query, or print browser database contents.

## Configuration ownership

The macOS format stores portable policy separately from macOS signer/helper/hash
facts and contains no Linux enforcement mode. The intended authoritative path
is:

```text
/Library/Application Support/Sensitive Data Firewall/config.json
```

The installed file will be root-owned and mode `0600`; the unprivileged GTK UI
receives a metadata-only review DTO and will apply changes through authenticated
control transport in Phase 05. The UI must never write this file directly.
Actual system-extension read/write acceptance remains blocked until valid
provisioning permits a running extension; no fallback to a user-writable policy
file is allowed.
