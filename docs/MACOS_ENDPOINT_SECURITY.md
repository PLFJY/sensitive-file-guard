# macOS Endpoint Security authorization backend

Phase 03 implements the narrow `ES_EVENT_TYPE_AUTH_OPEN` authorization
primitive. Phase 04 additionally subscribes to `NOTIFY_FORK`, `NOTIFY_EXEC`,
and `NOTIFY_EXIT` solely to maintain a bounded, stable-instance process graph.
There are no other authorization event subscriptions, and the backend is not
yet wired to browser or SSH product policy.

The C shim includes Apple's current SDK headers and exposes only client
lifecycle, AUTH_OPEN plus the three process-graph notifications, normalized facts,
retain/release, flags response, and Mach time conversion. Rust owns all state,
classification, deadlines, pending permissions, and health reporting. The shim
hardcodes `cache=false` and cannot make a product policy decision.

## Flags and responses

`es_event_open_t.fflag` contains kernel FFLAGS such as `FREAD` and `FWRITE`; it
is not an `open(2)` `O_RDONLY`/`O_RDWR` value. Immediate and deferred allow
responses return the exact requested FFLAGS. Deny returns zero. Every protected
response uses `es_respond_flags_result` with caching disabled.

A deferred `MacPendingPermission` retains its message before the ES callback
returns. Allow, deny, deadline, shutdown, and unresolved Drop race through one
atomic terminal transition. The winner responds once and releases once. Any
ES response error—including duplicate, not-found, wrong-event-type, or internal
failure—degrades backend health after releasing the retained message.

## Deadlines

Each event uses its own Mach absolute-time deadline and the active Darwin
timebase. The adjustable conservative constants are:

- `SAFETY_MARGIN = 1s`, reserved for scheduling and the final deny response;
- `MIN_INTERACTIVE_BUDGET = 2s`, below which no UI work may be attempted;
- `PRODUCT_MAX_PROMPT_CAP = 45s`, even when ES supplies a longer deadline.

The effective timer is `min(45s, remaining ES time - 1s)`. A usable interval of
2 seconds or less is denied immediately with a diagnostic. One scheduler thread
services all pending timers; it does not create an unbounded thread per open.

## Synthetic real-PoC

`scripts/macos/run-es-poc.sh` compiles a development-only exact fixture path and
one exact allowed probe executable into `guard-es`; the allow comparison also
requires the executable's `st_dev` and `st_ino` identity. It verifies that
`/usr/bin/cat` is denied and `guard-test-probe` is allowed. The script creates a
temporary synthetic canary only, uses no network, and explicitly deactivates
the extension on exit.

The script requires Apple-approved Endpoint Security provisioning, matching
host/extension profiles, Full Disk Access, and valid bundle/signing inputs. A
directly embedded entitlement claim without matching provisioning is not an
acceptance result.
