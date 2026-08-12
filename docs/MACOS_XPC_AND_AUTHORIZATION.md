# macOS authenticated XPC and human authorization

The macOS control channel is a single NSXPC method that exchanges bounded
`Data` values containing the existing versioned `guard-ipc` JSON envelope. It
does not duplicate the Rust protocol as Objective-C DTOs.

## Mach service

The Endpoint Security extension declares this explicit Info.plist entry:

```text
NSEndpointSecurityMachServiceName =
  top.plfjy.SensitiveFileGuard.guard-es.control
```

Custom bundle identifiers derive the value as
`<extension-bundle-id>.control`; the build passes the same value into Rust and
the plist template. This follows the installed `EndpointSecurity(7)` contract
and does not use the deprecated implicit `<TeamID>.<BundleID>.xpc` name.

## Peer authentication

Before activation, each accepted `NSXPCConnection` receives an exact
code-signing requirement. The server accepts only valid code from the same
runtime Team ID with one of these signing identifiers:

```text
<app-bundle-id>
<app-bundle-id>.guardctl
<app-bundle-id>.guard-notify
```

The client independently requires the exact extension signing identifier and
Team ID. Team ID alone, pathname, process name, and same UID alone are not
sufficient. The listener also checks the transport-reported effective UID
against the active console-user scope. No request JSON field supplies a UID or
signing identity.

The requirement text is constructed from validated identifier atoms and parsed
by Security.framework at startup. An ad-hoc signature has no Team ID and is
therefore deliberately unable to start or use authenticated production XPC.

## Bounds and concurrency

Requests are rejected above `guard_ipc::MAX_REQUEST_BYTES` (64 KiB), before
Rust JSON decoding. Rust validates the protocol version again. The native
listener caps in-flight handlers at 32. NSXPC connections remain independent,
so a metadata query is not queued behind a device-owner authentication dialog.

## Allow gate

`guard-client::macos::MacGuardClient` classifies operations using the shared
protocol enum. Metadata and Block/restrictive operations do not invoke an
authentication dialog. Every capability-expanding request invokes:

```text
LAContext + LAPolicyDeviceOwnerAuthentication
```

The request bytes are not sent until authentication succeeds. Cancellation,
failure, unavailability, or expiry sends no Allow. GTK passes the pending ES
expiry into this typed path; a late result fails before XPC resolution. The
CLI compatibility path always performs the same gate and has no `--yes`, file,
environment variable, cached token, or lower-level resolver option.

Block remains available without LocalAuthentication because it cannot expand
access. The extension remains responsible for atomically taking a pending ID,
revalidating its process/resource facts, creating any lease, and resolving the
held ES message. Shared pending stores consume an ID once, so a late or replayed
resolution cannot create a second lease.

Configuration replacement is also capability-expanding and therefore uses the
same LocalAuthentication gate. The extension accepts only browser and SSH scope
owned by the authenticated transport UID, validates canonical SSH paths without
reading key contents, and persists the authoritative JSON atomically under
`/Library/Application Support/Sensitive Data Firewall` with a mode-0700
directory and mode-0600 file. Configuration queries are filtered to the peer's
UID so another user's browser or SSH path metadata is not disclosed.

## Development diagnostics

The signed GTK host can query the service with:

```sh
Guard.app/Contents/MacOS/Guard --xpc-status
Guard.app/Contents/MacOS/guardctl status
```

Ad-hoc builds are expected to report that authenticated XPC is unavailable.
Formal builds use the Apple Team requirement. SIP-off self-use builds use the
exact local certificate fingerprint plus the expected Guard signing identifier;
same UID alone remains insufficient. A live service test requires one of those
authenticated identities and an activated Endpoint Security extension.

When an Apple Development signing identity is available, the transport-only
test can exercise the real Mach service without activating ES:

```sh
scripts/macos/test-xpc-auth.sh build/macos/Guard.app
```

It registers a temporary user launchd job, proves correctly signed Guard UI and
`guardctl` clients can exchange status requests, then proves both an ad-hoc
same-UID probe and a same-Team but unlisted-signing-ID probe get no response.
The script re-signs a temporary copy of the server without the restricted ES
entitlement and a temporary host executable without the
system-extension-install entitlement, removes the job and fixtures on exit,
and does not claim Endpoint Security/FDA acceptance.
