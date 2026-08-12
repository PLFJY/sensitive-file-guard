# macOS browser protection and migration

The macOS Endpoint Security extension classifies configured browser resources
before each protected `AUTH_OPEN`, resolves the opener from ES audit/process
facts, applies the portable policy, and responds without waiting for UI unless
a positively enrolled browser is importing another enrolled browser's data.

## Resource classification

Configuration activation performs one bounded discovery pass and builds an
inode index for existing critical files plus prefix entries for existing
storage/session trees. The hot path does not rescan a profile. It uses:

- `(st_dev, st_ino)` for existing concrete protected files;
- enrolled tree prefixes for descendants;
- the pure `guard-browser` Chromium/Firefox relative-path classifiers for a
  protected file or tree created after the index was built.

The dynamic classifier covers the same explicit resource set as the portable
registry. It does not classify browser cache directories.

Policy is disabled when no valid authoritative configuration is loaded. A
normal Protection switch changes only `policy_enabled`; the active ES client
then takes the unprotected fast path without changing extension lifecycle.

## Identity and decisions

Every protected event is evaluated with PID, audit-token process version,
start time, canonical executable path, executable device/inode, UID, exact
code-signing identity or explicit enrolled hash, and bounded ancestry when it
is available. Missing ancestry cannot create trust: it only prevents a process
from matching a descendant lease.

- exact enrolled browser/helper reading its own profile: allow requested
  FFLAGS;
- unknown process, wrong signer/path/hash, or wrong UID: deny immediately and
  do not prompt;
- exact enrolled Browser B reading Browser A: create a bounded pending request;
- valid process-tree migration lease: allow only the read flag.

## Interactive migration

The pending lifetime is the usable ES deadline minus the response safety
margin, capped by the product's 45-second macOS prompt limit. The portable
60-second pending default is not imposed on retained ES messages. A separate
deadline scheduler remains the final fail-closed owner of every retained ES
message.

Allow crosses LocalAuthentication in the signed UI client. The extension then
re-resolves the target's stable identity and UID, confirms the exact root is
still live, creates a ten-minute root-bound lease, and only then answers the
held open. Block, close, queue saturation, deadline expiry, process exit,
identity change, and resolution replay deny.

The short importer grace coalesces only requests already associated with the
same UID, source browser/profile, target browser, and exact target executable
identity. Every sibling root is independently re-resolved and receives its own
root-bound lease. A later unrelated root does not inherit an existing lease.

## Read-only FFLAGS guarantee

Darwin `FREAD` (`0x1`) and `FWRITE` (`0x2`) are kernel FFLAGS from
`<sys/fcntl.h>`; they are not `open(2)` `O_*` values. Own-profile browser opens
receive the exact requested mask. Every migration Allow and AllowByLease
response intersects the request with `FREAD`, so `FWRITE` is never authorized
for source-profile migration access. A write-only cross-browser request is
denied without prompting.

macOS status reports `read_only_guaranteed = true`. Linux remains unchanged and
does not make this guarantee.

## Audit and privacy

Audit submission is off the authorization hot path. Typed metadata-only codes
include:

- `browser_migration_confirmation_required`
- `browser_migration_allowed`
- `browser_migration_blocked`
- `browser_migration_timed_out`

Records contain resource kind/path and verified process metadata, never cookie
values, database rows, passwords, session tokens, or browser key material.

## Acceptance boundary

Synthetic tests cover all policy, timeout, queue, replay, identity, lease,
FFLAGS, and audit behavior without reading a real profile. Chrome and Firefox
were also started against separate temporary profiles and local `data:` pages;
their normal protected-class writes and observed signed helper topology were
verified.

Live proof that an unknown process is denied by the kernel and that a real
cross-browser importer succeeds after approval requires an activated SIP-off
self-use or formally provisioned Endpoint Security extension with Full Disk
Access. These end-to-end assertions remain BLOCKED until the controlled live
rerun and must not be reported as passed.

Run `scripts/macos/test-disposable-browsers.sh` for the entitlement-independent
Chrome/Firefox startup and signer check. On an activated test host, run
`scripts/macos/run-browser-policy-acceptance.sh`; it creates only mktemp-backed
profiles, refuses to continue without authenticated XPC, checks unknown-probe
denial, and guides the two explicit migration decisions before verifying typed
audit results.
